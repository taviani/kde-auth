package crypto

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type RSAIssuer struct {
	issuer     string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

func NewRSAIssuer(issuer, privatePEM, publicPEM string) (*RSAIssuer, error) {
	priv, err := parsePrivateKey(privatePEM)
	if err != nil {
		return nil, err
	}
	pub, err := parsePublicKey(publicPEM)
	if err != nil {
		return nil, err
	}
	return &RSAIssuer{
		issuer:     issuer,
		privateKey: priv,
		publicKey:  pub,
		keyID:      "kde-auth-1",
	}, nil
}

func (i *RSAIssuer) Issuer() string {
	return i.issuer
}

func (i *RSAIssuer) AccessToken(_ context.Context, claims port.AccessClaims) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":             i.issuer,
		"sub":             string(claims.Subject),
		"aud":             string(claims.Audience),
		"email":           claims.Email.String(),
		"email_verified":  claims.EmailVerified,
		"role":            string(claims.Role),
		"iat":             now.Unix(),
		"exp":             claims.ExpiresAt.Unix(),
	})
	token.Header["kid"] = i.keyID
	return token.SignedString(i.privateKey)
}

func (i *RSAIssuer) ParseAccessToken(_ context.Context, tokenString string) (port.AccessClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return i.publicKey, nil
	}, jwt.WithIssuer(i.issuer))
	if err != nil || !token.Valid {
		return port.AccessClaims{}, domain.ErrUnauthorized
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return port.AccessClaims{}, domain.ErrUnauthorized
	}
	sub, _ := claims["sub"].(string)
	aud, _ := claims["aud"].(string)
	email, _ := claims["email"].(string)
	role, _ := claims["role"].(string)
	verified, _ := claims["email_verified"].(bool)
	expFloat, _ := claims["exp"].(float64)
	return port.AccessClaims{
		Subject:       domain.UserID(sub),
		Audience:      domain.ClientID(aud),
		Email:         domain.Email(email),
		EmailVerified: verified,
		Role:          domain.Role(role),
		ExpiresAt:     time.Unix(int64(expFloat), 0),
	}, nil
}

func (i *RSAIssuer) JWKS(context.Context) (map[string]any, error) {
	n := base64URLEncode(i.publicKey.N.Bytes())
	e := base64URLEncode(bigIntToBytes(i.publicKey.E))

	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": i.keyID,
				"n":   n,
				"e":   e,
			},
		},
	}, nil
}

func parsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return priv, nil
}

func parsePublicKey(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return key, nil
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func bigIntToBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n & 0xff)}, out...)
		n >>= 8
	}
	return out
}

var _ port.TokenIssuer = (*RSAIssuer)(nil)
