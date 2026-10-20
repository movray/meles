package scan

import (
	"fmt"
	"sync"

	"git.itknecht.de/sugras/meles/internal/engine"
	"git.itknecht.de/sugras/meles/internal/extract"
)

// Cache keeps layer results in memory, keyed by layer diffID, engine and
// signature version and scan limits. A signature update therefore causes a
// rescan. The oldest entries are evicted beyond Max entries.
type Cache struct {
	Max int

	mu    sync.Mutex
	m     map[string]*layerResult
	order []string
}

// NewCache returns a cache holding at most max layers.
func NewCache(max int) *Cache {
	return &Cache{Max: max, m: map[string]*layerResult{}}
}

// Len returns the number of cached layers.
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

func (c *Cache) get(key string) (*layerResult, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[key]
	return r, ok
}

func (c *Cache) put(key string, r *layerResult) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[key]; ok {
		return
	}
	c.m[key] = r
	c.order = append(c.order, key)
	for c.Max > 0 && len(c.order) > c.Max {
		delete(c.m, c.order[0])
		c.order = c.order[1:]
	}
}

func cacheKey(diffID string, v engine.Version, lim extract.Limits) string {
	return fmt.Sprintf("%s|%s|%s|%d", diffID, v.Engine, v.Signatures, lim.MaxFileSize)
}
