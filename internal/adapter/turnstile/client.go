package turnstile

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type Client struct {
	secret string
	client *http.Client
}

func NewClient(secret string) *Client {
	return &Client{
		secret: secret,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) Verify(ctx context.Context, token, remoteIP string) error {
	if token == "" {
		return domain.ErrCaptchaFailed
	}
	form := url.Values{}
	form.Set("secret", c.secret)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var body struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	if !body.Success {
		return domain.ErrCaptchaFailed
	}
	return nil
}

var _ port.CaptchaVerifier = (*Client)(nil)
