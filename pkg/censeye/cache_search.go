package censeye

import (
	"encoding/json"

	"github.com/censys-research/censeye-ng/pkg/cache"
)

type cenqlKey struct{ cenql string }

func (c cenqlKey) Hash() string { return c.cenql }

// loadSearchCache attempts to load the search cache for a given CENQL query.
// it will deserialize the results from the cache and return them as a slice of host strings.
func (c *Censeye) loadSearchCache(cenql string) ([]string, bool) {
	obj := &cache.GenericCachable[[]string]{
		Key: cenqlKey{cenql: cenql},
		Enc: func(_ []string) []byte { return nil }, // not used for load
	}

	entry, err := c.cache.Load(obj)
	if err != nil {
		return nil, false
	}

	var ret []string
	if err := json.Unmarshal(entry.Bytes(), &ret); err != nil {
		return nil, false
	}

	return ret, true
}

// saveSearchCache uses the cachable generic to serialize the CENQL search results to disk.
// each string in the result is a single host that matched the query .
func (c *Censeye) saveSearchCache(cenql string, results []string) error {
	obj := &cache.GenericCachable[[]string]{
		Key:   cenqlKey{cenql: cenql},
		Value: results,
		Enc: func(s []string) []byte {
			data, err := json.Marshal(s)
			if err != nil {
				return nil
			}
			return data
		},
	}

	_, err := c.cache.Save(obj)
	return err
}
