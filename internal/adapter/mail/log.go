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

func (m *LogMailer) SendPasswordReset(_ context.Context, to domain.Email, resetURL string) error {
	log.Printf("mail: password reset for %s → %s", to, resetURL)
	return nil
}

func (m *LogMailer) SendInvite(_ context.Context, to domain.Email, appName, acceptURL string) error {
	log.Printf("mail: invite for %s app=%s → %s", to, appName, acceptURL)
	return nil
}

var _ port.Mailer = (*LogMailer)(nil)
