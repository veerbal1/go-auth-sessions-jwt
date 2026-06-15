package api

import "context"

type contextKey string

const userContextKey contextKey = "user"

type UserInfo struct {
	UserID    string
	Name      string
	Email     string
	SessionID string
	Roles     []string
}

func SetUser(ctx context.Context, u UserInfo) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

func GetUser(ctx context.Context) (UserInfo, bool) {
	u, ok := ctx.Value(userContextKey).(UserInfo)
	return u, ok
}
