package port

import "context"

type CaptchaVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}

type NoopCaptcha struct{}

func (NoopCaptcha) Verify(context.Context, string, string) error { return nil }
