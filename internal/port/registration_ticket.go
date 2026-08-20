package port

import (
	"context"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
)

type RegistrationTicketRepository interface {
	Create(ctx context.Context, ticket domain.RegistrationTicket, tokenHash string) error
	Peek(ctx context.Context, tokenHash string, at time.Time) (domain.RegistrationTicket, error)
	Consume(ctx context.Context, tokenHash string, at time.Time) (domain.RegistrationTicket, error)
}
