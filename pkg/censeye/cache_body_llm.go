package censeye

import (
	"encoding/json"

	"github.com/censys-research/censeye-ng/pkg/cache"
	log "github.com/sirupsen/logrus"
)

const bodyLLMCachePrefix = "body_llm:"

// bodyLLMKey is the cache key for LLM regex results keyed by body_hash_sha256.
type bodyLLMKey string

func (b bodyLLMKey) Hash() string {
	return bodyLLMCachePrefix + string(b)
}

// loadBodyLLMCache returns cached regex list for the given body_hash_sha256, or (nil, false) on miss/error.
func (c *Censeye) loadBodyLLMCache(bodyHash string) ([]string, bool) {
	obj := &cache.GenericCachable[[]string]{
		Key: bodyLLMKey(bodyHash),
		Enc: func(_ []string) []byte { return nil },
	}

	entry, err := c.cache.Load(obj)
	if err != nil {
		return nil, false
	}

	log.Debugf("Loaded body LLM cache for %s (age = %v)", bodyHash, entry.Age())

	var result []string
	if err := json.Unmarshal(entry.Bytes(), &result); err != nil {
		return nil, false
	}
	return result, true
}

// saveBodyLLMCache stores the regex list for the given body_hash_sha256.
func (c *Censeye) saveBodyLLMCache(bodyHash string, regexes []string) error {
	obj := &cache.GenericCachable[[]string]{
		Key:   bodyLLMKey(bodyHash),
		Value: regexes,
		Enc: func(v []string) []byte {
			b, _ := json.Marshal(v)
			return b
		},
	}
	_, err := c.cache.Save(obj)
	return err
}
