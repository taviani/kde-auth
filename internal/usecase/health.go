package usecase

import (
	"context"

	"github.com/taviani/kde-auth/internal/port"
)

type Health struct {
	checker port.HealthChecker
}

func NewHealth(checker port.HealthChecker) *Health {
	return &Health{checker: checker}
}

func (h *Health) Execute(ctx context.Context) error {
	return h.checker.Ping(ctx)
}
