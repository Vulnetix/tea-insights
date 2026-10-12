package teainsights

// A small thread-safe LRU with a per-entry TTL, holding compiled CEL programs
// and tenant inventories. No external dependency.

import (
	"container/list"
	"sync"
	"time"
)

type lruItem struct {
	key     string
	value   any
	expires time.Time
}

// lruCache is a fixed-capacity, TTL-bounded LRU.
type lruCache struct {
	mu    sync.Mutex
	cap   int
	ttl   time.Duration
	ll    *list.List
	items map[string]*list.Element
}

func newLRUCache(capacity int, ttl time.Duration) *lruCache {
	if capacity < 1 {
		capacity = 1
	}
	return &lruCache{
		cap:   capacity,
		ttl:   ttl,
		ll:    list.New(),
		items: make(map[string]*list.Element, capacity),
	}
}

// Get returns the cached value if present and not expired.
func (c *lruCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	it := el.Value.(*lruItem)
	if time.Now().After(it.expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return it.value, true
}

// Set inserts or updates a value, evicting the least-recently-used entry when
// over capacity.
func (c *lruCache) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := time.Now().Add(c.ttl)
	if el, ok := c.items[key]; ok {
		it := el.Value.(*lruItem)
		it.value = value
		it.expires = exp
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruItem{key: key, value: value, expires: exp})
	c.items[key] = el
	if c.ll.Len() > c.cap {
		if oldest := c.ll.Back(); oldest != nil {
			c.ll.Remove(oldest)
			delete(c.items, oldest.Value.(*lruItem).key)
		}
	}
}

// Delete drops one entry.
//
// A TTL is the right invalidation for a cache over data that changes on its
// own schedule. It is the wrong one for a cache a caller can invalidate
// precisely: a client that writes and immediately reads back must not be told
// its own write did not happen, and "wait for the TTL" is not an answer.
func (c *lruCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.Remove(el)
		delete(c.items, key)
	}
}
