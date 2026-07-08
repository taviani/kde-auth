package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Port           int
	Issuer         string
	DatabaseURL    string
	RegistrationOpen bool
}

func Load() (Config, error) {
	port, err := strconv.Atoi(getEnv("PORT", "3001"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid PORT: %w", err)
	}

	cfg := Config{
		Port:             port,
		Issuer:           os.Getenv("ISSUER"),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		RegistrationOpen: os.Getenv("REGISTRATION_OPEN") != "false",
	}

	if cfg.Issuer == "" {
		return Config{}, fmt.Errorf("ISSUER is required")
	}
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
