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
	var id domain.UserID
	err := r.pool.QueryRow(ctx, `
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
	return id, err
}

const selectUserByEmailSQL = `
SELECT id, email, password_hash, role, status, email_verified_at, created_at, updated_at
FROM users WHERE lower(email) = lower($1)
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
	tag, err := r.pool.Exec(ctx, `
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
	return nil
}

func (r *UserRepo) ExistsByEmail(ctx context.Context, email domain.Email) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE lower(email) = lower($1))`, email.String()).Scan(&exists)
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
