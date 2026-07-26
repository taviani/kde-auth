package mail

import (
	"strings"
	"testing"
)

func TestBuildMessage(t *testing.T) {
	t.Parallel()
	msg := string(buildMessage("noreply@example.com", "user@example.com", "Verify", "hello\n"))
	for _, want := range []string{
		"From: noreply@example.com\r\n",
		"To: user@example.com\r\n",
		"Subject: Verify\r\n",
		"Content-Type: text/plain; charset=UTF-8\r\n",
		"\r\nhello\n",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q\n%s", want, msg)
		}
	}
}

func TestNewFromConfigLogWhenEmpty(t *testing.T) {
	t.Parallel()
	m, err := NewFromConfig(SMTPConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.(*LogMailer); !ok {
		t.Fatalf("got %T, want *LogMailer", m)
	}
}

func TestNewSMTPMailerRequiresHostAndFrom(t *testing.T) {
	t.Parallel()
	if _, err := NewSMTPMailer(SMTPConfig{From: "a@b.c"}); err == nil {
		t.Fatal("expected error for empty host")
	}
	if _, err := NewSMTPMailer(SMTPConfig{Host: "smtp.example"}); err == nil {
		t.Fatal("expected error for empty from")
	}
}
