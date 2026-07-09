package port

import (
	"context"

	"github.com/taviani/kde-auth/internal/domain"
)

type Mailer interface {
	SendVerification(ctx context.Context, to domain.Email, verifyURL string) error
}
