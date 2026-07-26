package domain

import "time"

type UserAppAccess struct {
	UserID      UserID
	ClientID    ClientID
	EntryDomain string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

type UserStats struct {
	Total             int
	Pending           int
	Active            int
	Suspended         int
	Verified          int
	Unverified        int
	CreatedLast7Days  int
	CreatedLast30Days int
	ByClient          []ClientUserCount
}

type ClientUserCount struct {
	ClientID ClientID
	Name     string
	Count    int
}

type UserListFilter struct {
	Query    string
	Status   UserStatus
	Role     Role
	ClientID ClientID
	Limit    int
	Offset   int
}

func (u User) IsAdmin() bool {
	return u.Role == RoleAdmin
}
