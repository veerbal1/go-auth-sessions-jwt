package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func NormalizeIP(ip string) string {
	return strings.TrimSpace(ip)
}

func hashKey(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func LoginEmailKey(email string) string {
	return "login:email:" + hashKey(NormalizeEmail(email))
}

func LoginIPKey(ip string) string {
	return "login:ip:" + hashKey(NormalizeIP(ip))
}

func LoginEmailIPKey(email, ip string) string {
	combined := NormalizeEmail(email) + ":" + NormalizeIP(ip)
	return "login:email_ip:" + hashKey(combined)
}

func IncrementCounter(ctx context.Context, rdb *redis.Client, key string, limit int, ttl time.Duration) (int, bool, error) {
	count, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, false, fmt.Errorf("failed to increment counter: %w", err)
	}

	if count == 1 {
		if err := rdb.Expire(ctx, key, ttl).Err(); err != nil {
			return 0, false, fmt.Errorf("failed to set counter TTL: %w", err)
		}
	}

	exceeded := count > int64(limit)
	return int(count), exceeded, nil
}
