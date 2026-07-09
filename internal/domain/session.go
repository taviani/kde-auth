package domain

import "time"

type SessionID string

type Session struct {
	ID        SessionID
	UserID    UserID
	Token     string
	ExpiresAt time.Time
}

func (s Session) IsExpired(at time.Time) bool {
	return !at.Before(s.ExpiresAt)
}
