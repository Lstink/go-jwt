package cache

import (
	"context"
	"github.com/redis/go-redis/v9"
	"time"
)

const lockRetries = 5

func NewRedisCache(ctx context.Context, options *redis.Options) ICache {
	if options == nil {
		return nil
	}

	if options.Addr == "" {
		return nil
	}

	c := redis.NewClient(options)
	return &JRedis{
		Pool:        c,
		lockRetries: lockRetries,
		ctx:         ctx,
	}
}

type JRedis struct {
	Pool              *redis.Client
	defaultExpiration time.Duration
	lockRetries       int
	ctx               context.Context
}

func (r *JRedis) Set(key string, value string, expires time.Duration) error {
	result := r.Pool.Set(r.ctx, key, value, expires)
	return result.Err()
}

func (r *JRedis) Get(key string) (returnValue string, err error) {
	b, err := r.Pool.Get(r.ctx, key).Bytes()
	if err == redis.Nil {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(b), err
}

func (r *JRedis) Has(key string) bool {

	value, err := r.Get(key)
	if value != "" && err == nil {
		return true
	}

	return false
}

func (r *JRedis) Delete(key string) error {
	return r.Pool.Del(r.ctx, key).Err()
}
