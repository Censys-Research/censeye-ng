package censeye

import (
	"fmt"
	"time"

	"github.com/censys-research/censeye-ng/pkg/cache"
	"github.com/tidwall/gjson"
)

type hstKey struct {
	Host   string
	AtTime *time.Time
}

// loadHostCache attempts to load the host cache for a given host and time using the generic cache interface.
// TODO: in the future we should add a method to call the Age() method on the entry to determine if the cache
// is still valid.
func (c *Censeye) loadHostCache(host string, at *time.Time) (gjson.Result, bool) {
	obj := &cache.GenericCachable[string]{
		Key: hstKey{Host: host, AtTime: at},
		Enc: func(_ string) []byte { return nil },
	}

	entry, err := c.cache.Load(obj)
	if err != nil {
		return gjson.Result{}, false
	}

	return gjson.ParseBytes(entry.Bytes()), true
}

// saveHostCache uses the cachable generic to serialize the host data to disk
func (c *Censeye) saveHostCache(ip string, at *time.Time, data gjson.Result) error {
	obj := &cache.GenericCachable[string]{
		Key:   hstKey{Host: ip, AtTime: at},
		Value: data.Raw,
		Enc:   func(s string) []byte { return []byte(s) },
	}
	_, err := c.cache.Save(obj)
	return err
}

// Hash returns a string hash for the hstKey, used for the generic cache interface.
func (h hstKey) Hash() string {
	if h.AtTime == nil {
		return h.Host
	}

	return fmt.Sprintf("%s@%d", h.Host, h.AtTime.Unix())
}
