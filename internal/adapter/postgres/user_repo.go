package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

func (r *UserRepo) Create(ctx context.Context, user domain.User) (domain.UserID, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var id domain.UserID
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, role, status, email_verified_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`,
		user.Email.String(),
		user.PasswordHash.String(),
		user.Role,
		user.Status,
		user.EmailVerifiedAt,
		user.CreatedAt,
		user.UpdatedAt,
	).Scan(&id)
	if err != nil {
		return "", err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO user_emails (user_id, email, role, verified_at, created_at, updated_at)
		VALUES ($1, $2, 'primary', $3, $4, $5)
	`, id, user.Email.String(), user.EmailVerifiedAt, user.CreatedAt, user.UpdatedAt); err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}

const selectUserByEmailSQL = `
SELECT u.id, u.email, u.password_hash, u.role, u.status, u.email_verified_at, u.created_at, u.updated_at
FROM users u
INNER JOIN user_emails ue ON ue.user_id = u.id
WHERE lower(ue.email) = lower($1) AND ue.verified_at IS NOT NULL
`

func (r *UserRepo) ByEmail(ctx context.Context, email domain.Email) (domain.User, error) {
	row := r.pool.QueryRow(ctx, selectUserByEmailSQL, email.String())
	return scanUser(row)
}

const selectUserByIDSQL = `
SELECT id, email, password_hash, role, status, email_verified_at, created_at, updated_at
FROM users WHERE id = $1
`

func (r *UserRepo) ByID(ctx context.Context, id domain.UserID) (domain.User, error) {
	row := r.pool.QueryRow(ctx, selectUserByIDSQL, id)
	return scanUser(row)
}

func (r *UserRepo) MarkEmailVerified(ctx context.Context, id domain.UserID, at time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		UPDATE users
		SET status = $2, email_verified_at = $3, updated_at = $3
		WHERE id = $1
	`, id, domain.UserStatusActive, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	if _, err := tx.Exec(ctx, `
		UPDATE user_emails
		SET verified_at = $2, updated_at = $2
		WHERE user_id = $1 AND role = 'primary' AND verified_at IS NULL
	`, id, at); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *UserRepo) UpdatePassword(ctx context.Context, id domain.UserID, hash domain.PasswordHash, at time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1
	`, id, hash.String(), at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *UserRepo) ExistsByEmail(ctx context.Context, email domain.Email) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM user_emails WHERE lower(email) = lower($1))
	`, email.String()).Scan(&exists)
	return exists, err
}

func scanUser(row pgx.Row) (domain.User, error) {
	var u domain.User
	var email string
	var role, status string
	err := row.Scan(
		&u.ID,
		&email,
		&u.PasswordHash,
		&role,
		&status,
		&u.EmailVerifiedAt,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.User{}, err
	}
	u.Email = domain.Email(email)
	u.Role = domain.Role(role)
	u.Status = domain.UserStatus(status)
	return u, nil
}

var _ port.UserRepository = (*UserRepo)(nil)
