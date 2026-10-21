package scan

import (
	"fmt"
	"sync"

	"git.itknecht.de/sugras/meles/internal/engine"
	"git.itknecht.de/sugras/meles/internal/extract"
)

// Cache keeps layer results in memory, keyed by layer digest and diffID, engine and
// signature version and scan limits. A signature update therefore causes a
// rescan. The oldest entries are evicted beyond Max layers or MaxPaths
// paths: a layer result keeps every path of the layer for whiteout
// detection, so the number of paths, not layers, decides the memory use.
type Cache struct {
	Max      int
	MaxPaths int

	mu    sync.Mutex
	m     map[string]*layerResult
	order []string
	paths int
}

// DefaultMaxPaths keeps the cache at roughly 100-150 MiB.
const DefaultMaxPaths = 1_000_000

// NewCache returns a cache holding at most max layers and DefaultMaxPaths
// paths.
func NewCache(max int) *Cache {
	return &Cache{Max: max, MaxPaths: DefaultMaxPaths, m: map[string]*layerResult{}}
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
	c.paths += r.paths()
	for len(c.order) > 0 && (c.Max > 0 && len(c.order) > c.Max || c.MaxPaths > 0 && c.paths > c.MaxPaths) {
		c.paths -= c.m[c.order[0]].paths()
		delete(c.m, c.order[0])
		c.order = c.order[1:]
	}
}

// paths returns the number of paths r keeps in memory.
func (r *layerResult) paths() int {
	return len(r.meta.Entries) + len(r.meta.Whiteouts) + len(r.meta.Opaques) + len(r.meta.Skipped) + len(r.hits) + len(r.limited)
}

func cacheKey(digest, diffID string, v engine.Version, lim extract.Limits) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d", digest, diffID, v.Engine, v.Signatures, lim.MaxFileSize)
}
