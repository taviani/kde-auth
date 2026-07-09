package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/taviani/kde-auth/internal/adapter/clock"
	"github.com/taviani/kde-auth/internal/adapter/crypto"
	httpadapter "github.com/taviani/kde-auth/internal/adapter/http"
	"github.com/taviani/kde-auth/internal/adapter/http/handler"
	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/adapter/mail"
	"github.com/taviani/kde-auth/internal/adapter/postgres"
	"github.com/taviani/kde-auth/internal/adapter/turnstile"
	"github.com/taviani/kde-auth/internal/platform/config"
	"github.com/taviani/kde-auth/internal/port"
	"github.com/taviani/kde-auth/internal/usecase"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer pool.Close()

	if err := postgres.Migrate(ctx, pool, cfg.MigrationsPath); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	sysClock := clock.NewSystem()
	hasher := crypto.NewArgon2Hasher()
	issuer, err := crypto.NewRSAIssuer(cfg.Issuer, cfg.JWTPrivateKeyPEM, cfg.JWTPublicKeyPEM)
	if err != nil {
		log.Fatalf("jwt: %v", err)
	}

	userRepo := postgres.NewUserRepo(pool)
	clientRepo := postgres.NewClientRepo(pool)
	sessionRepo := postgres.NewSessionRepo(pool)
	tokenRepo := postgres.NewTokenRepo(pool)
	healthChecker := postgres.NewHealth(pool)

	seed := postgres.NewSeed(clientRepo, hasher)
	if err := seed.OAuthClient(ctx, postgres.OAuthClientSeed{
		ClientID:     cfg.OAuthClientID,
		ClientSecret: cfg.OAuthClientSecret,
		Name:         cfg.OAuthClientName,
		RedirectURI:  cfg.OAuthRedirectURI,
	}); err != nil {
		log.Fatalf("seed oauth client: %v", err)
	}

	mailer := mail.NewLogMailer()
	captcha := captchaVerifier(cfg)

	sessionTTL := time.Duration(cfg.SessionTTL) * time.Hour

	healthUC := usecase.NewHealth(healthChecker)
	registerUC := usecase.NewRegisterUser(userRepo, hasher, tokenRepo, mailer, captcha, sysClock, issuer, cfg.RegistrationOpen)
	verifyUC := usecase.NewVerifyEmail(userRepo, tokenRepo, sysClock)
	loginUC := usecase.NewLogin(userRepo, sessionRepo, hasher, captcha, sysClock, sessionTTL)
	logoutUC := usecase.NewLogout(sessionRepo, sysClock)
	resolveSessionUC := usecase.NewResolveSession(sessionRepo, userRepo, sysClock)
	authorizeUC := usecase.NewAuthorize(clientRepo, tokenRepo, resolveSessionUC, sysClock)
	tokenUC := usecase.NewExchangeToken(clientRepo, tokenRepo, userRepo, hasher, issuer, sysClock)
	userInfoUC := usecase.NewUserInfo(issuer, userRepo)
	oidcUC := usecase.NewOIDCMetadata(issuer)

	renderer, err := render.New()
	if err != nil {
		log.Fatalf("templates: %v", err)
	}

	router := httpadapter.NewRouter(cfg, httpadapter.Handlers{
		Health:      handler.NewHealth(healthUC),
		Register:    handler.NewRegister(registerUC, renderer, cfg.TurnstileSiteKey),
		Login:       handler.NewLogin(loginUC, renderer, cfg.TurnstileSiteKey, cfg.CookieSecure),
		VerifyEmail: handler.NewVerifyEmail(verifyUC),
		Logout:      handler.NewLogout(logoutUC, cfg.CookieSecure),
		Authorize:   handler.NewAuthorize(authorizeUC),
		Token:       handler.NewToken(tokenUC),
		UserInfo:    handler.NewUserInfo(userInfoUC, issuer),
		OIDC:        handler.NewOIDC(oidcUC, issuer),
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("kde-auth listening on %s (issuer %s)", srv.Addr, cfg.Issuer)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown: %v", err)
	}
}

func captchaVerifier(cfg config.Config) port.CaptchaVerifier {
	if cfg.TurnstileSecret == "" {
		return port.NoopCaptcha{}
	}
	return turnstile.NewClient(cfg.TurnstileSecret)
}
