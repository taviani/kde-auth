package domain

const MinPasswordLength = 12

type PlainPassword string

func NewPlainPassword(raw string) (PlainPassword, error) {
	if len(raw) < MinPasswordLength {
		return "", ValidationError{Field: "password", Message: "password must be at least 12 characters"}
	}
	return PlainPassword(raw), nil
}

type PasswordHash string

func (h PasswordHash) String() string {
	return string(h)
}
