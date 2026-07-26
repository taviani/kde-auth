package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type UserAdminRepo struct {
	pool *pgxpool.Pool
}

func NewUserAdminRepo(pool *pgxpool.Pool) *UserAdminRepo {
	return &UserAdminRepo{pool: pool}
}

func (r *UserAdminRepo) List(ctx context.Context, filter domain.UserListFilter) ([]domain.User, error) {
	where, args := userFilterSQL(filter)
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	limitIdx := len(args) - 1
	offsetIdx := len(args)

	q := fmt.Sprintf(`
		SELECT DISTINCT u.id, u.email, u.password_hash, u.role, u.status, u.email_verified_at, u.created_at, u.updated_at
		FROM users u
		%s
		%s
		ORDER BY u.created_at DESC
		LIMIT $%d OFFSET $%d
	`, userFilterJoin(filter), where, limitIdx, offsetIdx)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r *UserAdminRepo) Count(ctx context.Context, filter domain.UserListFilter) (int, error) {
	where, args := userFilterSQL(filter)
	q := fmt.Sprintf(`
		SELECT COUNT(DISTINCT u.id)
		FROM users u
		%s
		%s
	`, userFilterJoin(filter), where)
	var n int
	err := r.pool.QueryRow(ctx, q, args...).Scan(&n)
	return n, err
}

func (r *UserAdminRepo) Stats(ctx context.Context, now time.Time) (domain.UserStats, error) {
	var s domain.UserStats
	err := r.pool.QueryRow(ctx, `
		SELECT
			COUNT(*)::int,
			COUNT(*) FILTER (WHERE status = 'pending')::int,
			COUNT(*) FILTER (WHERE status = 'active')::int,
			COUNT(*) FILTER (WHERE status = 'suspended')::int,
			COUNT(*) FILTER (WHERE email_verified_at IS NOT NULL)::int,
			COUNT(*) FILTER (WHERE email_verified_at IS NULL)::int,
			COUNT(*) FILTER (WHERE created_at >= $1)::int,
			COUNT(*) FILTER (WHERE created_at >= $2)::int
		FROM users
	`, now.Add(-7*24*time.Hour), now.Add(-30*24*time.Hour)).Scan(
		&s.Total, &s.Pending, &s.Active, &s.Suspended,
		&s.Verified, &s.Unverified, &s.CreatedLast7Days, &s.CreatedLast30Days,
	)
	if err != nil {
		return domain.UserStats{}, err
	}

	rows, err := r.pool.Query(ctx, `
		SELECT a.client_id, COALESCE(c.name, a.client_id), COUNT(DISTINCT a.user_id)::int
		FROM user_app_accesses a
		LEFT JOIN oauth_clients c ON c.client_id = a.client_id
		GROUP BY a.client_id, c.name
		ORDER BY COUNT(DISTINCT a.user_id) DESC, a.client_id
	`)
	if err != nil {
		return domain.UserStats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item domain.ClientUserCount
		var name string
		if err := rows.Scan(&item.ClientID, &name, &item.Count); err != nil {
			return domain.UserStats{}, err
		}
		item.Name = name
		s.ByClient = append(s.ByClient, item)
	}
	return s, rows.Err()
}

func (r *UserAdminRepo) SetStatus(ctx context.Context, id domain.UserID, status domain.UserStatus, at time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE users SET status = $2, updated_at = $3 WHERE id = $1
	`, id, status, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *UserAdminRepo) ListClientIDsForUsers(ctx context.Context, userIDs []domain.UserID) (map[domain.UserID][]domain.ClientID, error) {
	out := make(map[domain.UserID][]domain.ClientID)
	if len(userIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(userIDs))
	for i, id := range userIDs {
		ids[i] = string(id)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT user_id, client_id
		FROM user_app_accesses
		WHERE user_id = ANY($1::uuid[])
		ORDER BY last_seen_at DESC
	`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var uid domain.UserID
		var cid domain.ClientID
		if err := rows.Scan(&uid, &cid); err != nil {
			return nil, err
		}
		out[uid] = append(out[uid], cid)
	}
	return out, rows.Err()
}

func userFilterJoin(filter domain.UserListFilter) string {
	if filter.ClientID != "" {
		return `INNER JOIN user_app_accesses a ON a.user_id = u.id`
	}
	return ""
}

func userFilterSQL(filter domain.UserListFilter) (string, []any) {
	var parts []string
	var args []any
	n := 1
	if filter.ClientID != "" {
		parts = append(parts, fmt.Sprintf("a.client_id = $%d", n))
		args = append(args, string(filter.ClientID))
		n++
	}
	if q := strings.TrimSpace(filter.Query); q != "" {
		parts = append(parts, fmt.Sprintf("u.email ILIKE $%d", n))
		args = append(args, "%"+q+"%")
		n++
	}
	if filter.Status != "" {
		parts = append(parts, fmt.Sprintf("u.status = $%d", n))
		args = append(args, string(filter.Status))
		n++
	}
	if filter.Role != "" {
		parts = append(parts, fmt.Sprintf("u.role = $%d", n))
		args = append(args, string(filter.Role))
		n++
	}
	if len(parts) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(parts, " AND "), args
}

var _ port.UserAdminRepository = (*UserAdminRepo)(nil)
