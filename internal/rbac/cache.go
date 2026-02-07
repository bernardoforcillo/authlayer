package rbac

import (
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type cacheEntry struct {
	permissions []string
	expiresAt   time.Time
}

// Cache is an in-memory permission cache with TTL.
type Cache struct {
	store sync.Map
	ttl   time.Duration
}

// NewCache creates a new cache with the given TTL.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{ttl: ttl}
}

func cacheKey(userID uuid.UUID, orgID *uuid.UUID) string {
	if orgID != nil {
		return "user:" + userID.String() + ":org:" + orgID.String()
	}
	return "user:" + userID.String() + ":global"
}

// Get returns cached permissions if they exist and are not expired.
func (c *Cache) Get(key string) ([]string, bool) {
	val, ok := c.store.Load(key)
	if !ok {
		return nil, false
	}
	entry := val.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.store.Delete(key)
		return nil, false
	}
	return entry.permissions, true
}

// Set stores permissions in the cache.
func (c *Cache) Set(key string, permissions []string) {
	c.store.Store(key, &cacheEntry{
		permissions: permissions,
		expiresAt:   time.Now().Add(c.ttl),
	})
}

// Invalidate removes a specific cache entry.
func (c *Cache) Invalidate(key string) {
	c.store.Delete(key)
}

// InvalidateUser removes all cache entries for a user.
func (c *Cache) InvalidateUser(userID uuid.UUID) {
	prefix := "user:" + userID.String()
	c.store.Range(func(key, value interface{}) bool {
		if k, ok := key.(string); ok && strings.HasPrefix(k, prefix) {
			c.store.Delete(key)
		}
		return true
	})
}
