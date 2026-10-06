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

type UserEmailRepo struct {
	pool *pgxpool.Pool
}

func NewUserEmailRepo(pool *pgxpool.Pool) *UserEmailRepo {
	return &UserEmailRepo{pool: pool}
}

func (r *UserEmailRepo) ListByUser(ctx context.Context, userID domain.UserID) ([]domain.UserEmail, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, email, role, verified_at, created_at, updated_at
		FROM user_emails
		WHERE user_id = $1
		ORDER BY CASE role WHEN 'primary' THEN 0 ELSE 1 END, created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.UserEmail
	for rows.Next() {
		ue, err := scanUserEmail(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ue)
	}
	return out, rows.Err()
}

func (r *UserEmailRepo) ByEmail(ctx context.Context, email domain.Email) (domain.UserEmail, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, user_id, email, role, verified_at, created_at, updated_at
		FROM user_emails
		WHERE lower(email) = lower($1)
	`, email.String())
	return scanUserEmail(row)
}

func (r *UserEmailRepo) HasSecondary(ctx context.Context, userID domain.UserID) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM user_emails
			WHERE user_id = $1 AND role = 'secondary'
		)
	`, userID).Scan(&exists)
	return exists, err
}

func (r *UserEmailRepo) CountVerified(ctx context.Context, userID domain.UserID) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_emails
		WHERE user_id = $1 AND verified_at IS NOT NULL
	`, userID).Scan(&n)
	return n, err
}

func (r *UserEmailRepo) InsertPendingSecondary(ctx context.Context, userID domain.UserID, email domain.Email, at time.Time) (domain.UserEmail, error) {
	var ue domain.UserEmail
	var emailStr, role string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO user_emails (user_id, email, role, verified_at, created_at, updated_at)
		VALUES ($1, $2, 'secondary', NULL, $3, $3)
		RETURNING id, user_id, email, role, verified_at, created_at, updated_at
	`, userID, email.String(), at).Scan(
		&ue.ID, &ue.UserID, &emailStr, &role, &ue.VerifiedAt, &ue.CreatedAt, &ue.UpdatedAt,
	)
	if err != nil {
		return domain.UserEmail{}, err
	}
	ue.Email = domain.Email(emailStr)
	ue.Role = domain.EmailRole(role)
	return ue, nil
}

func (r *UserEmailRepo) MarkVerified(ctx context.Context, userID domain.UserID, email domain.Email, at time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE user_emails
		SET verified_at = $3, updated_at = $3
		WHERE user_id = $1 AND lower(email) = lower($2) AND verified_at IS NULL
	`, userID, email.String(), at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *UserEmailRepo) DeletePendingSecondary(ctx context.Context, userID domain.UserID) error {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM user_emails
		WHERE user_id = $1 AND role = 'secondary' AND verified_at IS NULL
	`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// DeleteVerified removes a verified address. If it was primary, promotes the other
// verified email to primary and syncs users.email / email_verified_at.
func (r *UserEmailRepo) DeleteVerified(ctx context.Context, userID domain.UserID, email domain.Email, at time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var role string
	var verifiedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT role, verified_at FROM user_emails
		WHERE user_id = $1 AND lower(email) = lower($2)
		FOR UPDATE
	`, userID, email.String()).Scan(&role, &verifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}
	if verifiedAt == nil {
		return domain.ValidationError{Field: "email", Message: "email is not verified"}
	}

	var verifiedCount int
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_emails
		WHERE user_id = $1 AND verified_at IS NOT NULL
	`, userID).Scan(&verifiedCount); err != nil {
		return err
	}
	if verifiedCount < 2 {
		return domain.ErrCannotDeleteLastEmail
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM user_emails
		WHERE user_id = $1 AND lower(email) = lower($2)
	`, userID, email.String()); err != nil {
		return err
	}

	if role == string(domain.EmailRolePrimary) {
		var remainingEmail string
		var remainingVerifiedAt time.Time
		err = tx.QueryRow(ctx, `
			SELECT email, verified_at FROM user_emails
			WHERE user_id = $1 AND verified_at IS NOT NULL
			LIMIT 1
			FOR UPDATE
		`, userID).Scan(&remainingEmail, &remainingVerifiedAt)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE user_emails
			SET role = 'primary', updated_at = $2
			WHERE user_id = $1 AND lower(email) = lower($3)
		`, userID, at, remainingEmail); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE users
			SET email = $2, email_verified_at = $3, updated_at = $4
			WHERE id = $1
		`, userID, remainingEmail, remainingVerifiedAt, at); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

type scannable interface {
	Scan(dest ...any) error
}

func scanUserEmail(row scannable) (domain.UserEmail, error) {
	var ue domain.UserEmail
	var emailStr, role string
	err := row.Scan(
		&ue.ID, &ue.UserID, &emailStr, &role, &ue.VerifiedAt, &ue.CreatedAt, &ue.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.UserEmail{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.UserEmail{}, err
	}
	ue.Email = domain.Email(emailStr)
	ue.Role = domain.EmailRole(role)
	return ue, nil
}

var _ port.UserEmailRepository = (*UserEmailRepo)(nil)
