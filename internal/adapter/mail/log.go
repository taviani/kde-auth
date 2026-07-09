package mail

import (
	"context"
	"log"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type LogMailer struct{}

func NewLogMailer() *LogMailer {
	return &LogMailer{}
}

func (m *LogMailer) SendVerification(_ context.Context, to domain.Email, verifyURL string) error {
	log.Printf("mail: verification for %s → %s", to, verifyURL)
	return nil
}

var _ port.Mailer = (*LogMailer)(nil)
