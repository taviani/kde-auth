package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type SMTPMailer struct {
	cfg SMTPConfig
}

func NewSMTPMailer(cfg SMTPConfig) (*SMTPMailer, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, fmt.Errorf("SMTP from is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 587
	}
	return &SMTPMailer{cfg: cfg}, nil
}

// NewFromConfig returns the log mailer when SMTP_HOST is empty, otherwise SMTP.
func NewFromConfig(cfg SMTPConfig) (port.Mailer, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return NewLogMailer(), nil
	}
	return NewSMTPMailer(cfg)
}

func (m *SMTPMailer) SendVerification(ctx context.Context, to domain.Email, verifyURL string) error {
	subject := "Verify your account"
	body := fmt.Sprintf(
		"Hello,\n\nPlease verify your email by opening this link:\n\n%s\n\nIf you did not create an account, you can ignore this message.\n",
		verifyURL,
	)
	return m.send(ctx, to, subject, body)
}

func (m *SMTPMailer) SendPasswordReset(ctx context.Context, to domain.Email, resetURL string) error {
	subject := "Reset your password"
	body := fmt.Sprintf(
		"Hello,\n\nReset your password by opening this link:\n\n%s\n\nIf you did not request a reset, you can ignore this message. The link expires in one hour.\n",
		resetURL,
	)
	return m.send(ctx, to, subject, body)
}

func (m *SMTPMailer) send(ctx context.Context, to domain.Email, subject, body string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	msg := buildMessage(m.cfg.From, to.String(), subject, body)
	addr := net.JoinHostPort(m.cfg.Host, fmt.Sprintf("%d", m.cfg.Port))

	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}

	if m.cfg.Port == 465 {
		return m.sendImplicitTLS(addr, auth, to.String(), msg)
	}
	return smtp.SendMail(addr, auth, m.cfg.From, []string{to.String()}, msg)
}

func (m *SMTPMailer) sendImplicitTLS(addr string, auth smtp.Auth, to string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: m.cfg.Host}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(m.cfg.From); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

var _ port.Mailer = (*SMTPMailer)(nil)
