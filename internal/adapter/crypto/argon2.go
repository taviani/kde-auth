package crypto

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

type Argon2Hasher struct{}

func NewArgon2Hasher() *Argon2Hasher {
	return &Argon2Hasher{}
}

func (h *Argon2Hasher) Hash(_ context.Context, password domain.PlainPassword) (domain.PasswordHash, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := randRead(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return domain.PasswordHash(encoded), nil
}

func (h *Argon2Hasher) Verify(stored domain.PasswordHash, password domain.PlainPassword) bool {
	salt, hash, params, ok := decodeArgon2ID(string(stored))
	if !ok {
		return false
	}
	other := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(hash)))
	return subtleConstantTimeCompare(hash, other)
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func decodeArgon2ID(encoded string) (salt, hash []byte, params argonParams, ok bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, params, false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, params, false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.time, &params.threads); err != nil {
		return nil, nil, params, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, params, false
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, params, false
	}
	return salt, hash, params, true
}

func randRead(buf []byte) (int, error) {
	return rand.Read(buf)
}

func subtleConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

var _ port.PasswordHasher = (*Argon2Hasher)(nil)
