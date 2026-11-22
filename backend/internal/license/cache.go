package license

import "sync"

// ResolverCache is the in-memory cache shared by the registry license
// resolvers: cache key → license expression or NegativeCacheValue. It is
// persisted to registry_license_cache, so only definite answers may enter it:
// a transient failure (timeout, 429, 5xx, decode error) cached as "" would be
// preloaded by every worker and never retried.
type ResolverCache struct {
	m          sync.Map
	newMu      sync.Mutex
	newEntries map[string]string
}

func (c *ResolverCache) recordNew(key, value string) {
	c.newMu.Lock()
	defer c.newMu.Unlock()
	if c.newEntries == nil {
		c.newEntries = make(map[string]string)
	}
	c.newEntries[key] = value
}

// Load returns the cached license (empty for a negative result) and, for a
// negative result, its reason.
func (c *ResolverCache) Load(key string) (lic, reason string, ok bool) {
	v, ok := c.LoadValue(key)
	if !ok {
		return "", "", false
	}
	lic, reason = SplitCacheValue(v)
	return lic, reason, true
}

// LoadValue returns the raw cache encoding.
func (c *ResolverCache) LoadValue(key string) (string, bool) {
	v, ok := c.m.Load(key)
	if !ok {
		return "", false
	}
	return v.(string), true
}

// StoreResult caches a license, or a negative result with its reason. A
// negative without a reason is not a definite answer and is not cached.
func (c *ResolverCache) StoreResult(key, lic, reason string) {
	if lic != "" {
		c.StoreValue(key, lic)
		return
	}
	c.StoreValue(key, NegativeCacheValue(reason))
}

// StoreValue caches a raw encoding; "" (no definite answer) is dropped.
func (c *ResolverCache) StoreValue(key, value string) {
	if value == "" {
		return
	}
	c.m.Store(key, value)
	c.recordNew(key, value)
}

// Reason returns the recorded reason of a cached negative result, "" otherwise.
func (c *ResolverCache) Reason(key string) string {
	_, reason, _ := c.Load(key)
	return reason
}

// PreloadCache seeds the cache (e.g. from ClickHouse). Rows with an empty
// value are legacy transient failures and are skipped so they get retried.
// Preloaded entries are not marked as new.
func (c *ResolverCache) PreloadCache(entries map[string]string) {
	for k, v := range entries {
		if v != "" {
			c.m.Store(k, v)
		}
	}
}

// CacheEntries exports the full cache for persistence.
func (c *ResolverCache) CacheEntries() map[string]string {
	out := make(map[string]string)
	c.m.Range(func(k, v any) bool {
		out[k.(string)] = v.(string)
		return true
	})
	return out
}

// NewCacheEntries returns and drains newly added cache entries since the last call.
// Preloaded entries are excluded, ensuring only new or changed items are persisted.
func (c *ResolverCache) NewCacheEntries() map[string]string {
	c.newMu.Lock()
	defer c.newMu.Unlock()
	if len(c.newEntries) == 0 {
		return nil
	}
	out := c.newEntries
	c.newEntries = nil
	return out
}
