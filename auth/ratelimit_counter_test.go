package auth

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func testRedis(t *testing.T) *redis.Client {
	t.Helper()

	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis not available, skipping test: %v", err)
	}
	return rdb
}

var counterSeq int

func uniqueTestKey() string {
	counterSeq++
	return fmt.Sprintf("test:ratelimit:%d", time.Now().UnixNano()+int64(counterSeq))
}

func TestIncrementCounterFirstIncrement(t *testing.T) {
	rdb := testRedis(t)
	ctx := context.Background()
	key := uniqueTestKey()
	defer rdb.Del(ctx, key)

	count, exceeded, err := IncrementCounter(ctx, rdb, key, 5, time.Minute)
	if err != nil {
		t.Fatalf("IncrementCounter failed: %v", err)
	}

	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if exceeded {
		t.Error("must not be exceeded on first increment")
	}

	ttl, err := rdb.TTL(ctx, key).Result()
	if err != nil {
		t.Fatalf("TTL failed: %v", err)
	}
	if ttl <= 0 {
		t.Error("TTL must be set after first increment")
	}
}

func TestIncrementCounterIncreasesCount(t *testing.T) {
	rdb := testRedis(t)
	ctx := context.Background()
	key := uniqueTestKey()
	defer rdb.Del(ctx, key)

	for i := 1; i <= 3; i++ {
		count, exceeded, err := IncrementCounter(ctx, rdb, key, 5, time.Minute)
		if err != nil {
			t.Fatalf("increment %d failed: %v", i, err)
		}
		if count != i {
			t.Errorf("increment %d: count = %d, want %d", i, count, i)
		}
		if exceeded {
			t.Errorf("increment %d: must not be exceeded", i)
		}
	}
}

func TestIncrementCounterExceeded(t *testing.T) {
	rdb := testRedis(t)
	ctx := context.Background()
	key := uniqueTestKey()
	defer rdb.Del(ctx, key)

	limit := 3
	// increment up to limit
	for i := 0; i < limit; i++ {
		_, exceeded, err := IncrementCounter(ctx, rdb, key, limit, time.Minute)
		if err != nil {
			t.Fatalf("increment failed: %v", err)
		}
		if exceeded {
			t.Errorf("must not be exceeded at count %d", i+1)
		}
	}

	// one more should exceed
	_, exceeded, err := IncrementCounter(ctx, rdb, key, limit, time.Minute)
	if err != nil {
		t.Fatalf("increment failed: %v", err)
	}
	if !exceeded {
		t.Error("must be exceeded after limit")
	}
}

func TestIncrementCounterSeparateKeys(t *testing.T) {
	rdb := testRedis(t)
	ctx := context.Background()
	key1 := uniqueTestKey()
	key2 := uniqueTestKey()
	defer rdb.Del(ctx, key1, key2)

	count1, _, _ := IncrementCounter(ctx, rdb, key1, 5, time.Minute)
	count2, _, _ := IncrementCounter(ctx, rdb, key2, 5, time.Minute)

	if count1 != 1 {
		t.Errorf("key1 count = %d, want 1", count1)
	}
	if count2 != 1 {
		t.Errorf("key2 count = %d, want 1", count2)
	}
}
