package domain

import "time"

type EmailRole string

const (
	EmailRolePrimary   EmailRole = "primary"
	EmailRoleSecondary EmailRole = "secondary"
)

type UserEmailID string

type UserEmail struct {
	ID         UserEmailID
	UserID     UserID
	Email      Email
	Role       EmailRole
	VerifiedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (e UserEmail) IsVerified() bool {
	return e.VerifiedAt != nil
}

func (e UserEmail) IsPending() bool {
	return e.VerifiedAt == nil
}
