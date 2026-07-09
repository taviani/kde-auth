package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port             int
	Issuer           string
	DatabaseURL      string
	MigrationsPath   string
	RegistrationOpen bool
	CookieSecure     bool
	SessionTTL       int // hours

	JWTPrivateKeyPEM string
	JWTPublicKeyPEM  string

	OAuthClientID       string
	OAuthClientSecret   string
	OAuthClientName     string
	OAuthRedirectURI    string

	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string

	TurnstileSecret  string
	TurnstileSiteKey string
}

func Load() (Config, error) {
	port, err := strconv.Atoi(getEnv("PORT", "3001"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid PORT: %w", err)
	}

	smtpPort, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid SMTP_PORT: %w", err)
	}

	sessionTTL, err := strconv.Atoi(getEnv("SESSION_TTL_HOURS", "24"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid SESSION_TTL_HOURS: %w", err)
	}

	cfg := Config{
		Port:             port,
		Issuer:           strings.TrimRight(os.Getenv("ISSUER"), "/"),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		MigrationsPath:   getEnv("MIGRATIONS_PATH", "migrations"),
		RegistrationOpen: os.Getenv("REGISTRATION_OPEN") != "false",
		CookieSecure:     os.Getenv("COOKIE_SECURE") == "true",
		SessionTTL:       sessionTTL,
		JWTPrivateKeyPEM: os.Getenv("JWT_PRIVATE_KEY"),
		JWTPublicKeyPEM:  os.Getenv("JWT_PUBLIC_KEY"),
		OAuthClientID:       getEnv("OAUTH_CLIENT_ID", "dept-app"),
		OAuthClientSecret:   os.Getenv("OAUTH_CLIENT_SECRET"),
		OAuthClientName:     getEnv("OAUTH_CLIENT_NAME", "Department App"),
		OAuthRedirectURI:    os.Getenv("OAUTH_REDIRECT_URI"),
		SMTPHost:            os.Getenv("SMTP_HOST"),
		SMTPPort:            smtpPort,
		SMTPUser:            os.Getenv("SMTP_USER"),
		SMTPPassword:        os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:            os.Getenv("SMTP_FROM"),
		TurnstileSecret:     os.Getenv("TURNSTILE_SECRET"),
		TurnstileSiteKey:    os.Getenv("TURNSTILE_SITE_KEY"),
	}

	if cfg.Issuer == "" {
		return Config{}, fmt.Errorf("ISSUER is required")
	}
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}

	if cfg.JWTPrivateKeyPEM == "" || cfg.JWTPublicKeyPEM == "" {
		if !isLocalIssuer(cfg.Issuer) {
			return Config{}, fmt.Errorf("JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required in production")
		}
		priv, pub, err := generateDevRSAKeys()
		if err != nil {
			return Config{}, fmt.Errorf("generate dev JWT keys: %w", err)
		}
		cfg.JWTPrivateKeyPEM = priv
		cfg.JWTPublicKeyPEM = pub
	}

	if cfg.OAuthClientSecret == "" {
		if isLocalIssuer(cfg.Issuer) {
			cfg.OAuthClientSecret = "dev-secret-change-me-16"
		} else {
			return Config{}, fmt.Errorf("OAUTH_CLIENT_SECRET is required")
		}
	}
	if cfg.OAuthRedirectURI == "" && isLocalIssuer(cfg.Issuer) {
		cfg.OAuthRedirectURI = "http://localhost:4322/auth/callback"
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func isLocalIssuer(issuer string) bool {
	return strings.Contains(issuer, "localhost") || strings.Contains(issuer, "127.0.0.1")
}

func generateDevRSAKeys() (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	priv := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return string(priv), string(pub), nil
}
