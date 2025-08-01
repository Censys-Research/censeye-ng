package censeye

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/censys-research/censeye-ng/pkg/cache"
	"github.com/censys/censys-sdk-go/models/components"
	log "github.com/sirupsen/logrus"
)

type fpkSet []components.FieldValuePair

// loadRuleCache attempts to load the rule cache for a given set of field-value pairs
// TODO: in the future we should add a method to call the Age() method on the entry to determine if the cache
func (c *Censeye) loadRuleCache(pairs []components.FieldValuePair) (uint64, bool) {
	obj := &cache.GenericCachable[uint64]{
		Key: fpkSet(pairs),
		Enc: func(_ uint64) []byte { return nil }, // not used in Load
	}

	ent, err := c.cache.Load(obj)
	if err != nil {
		return 0, false
	}

	log.Debugf("Loaded cache for %v (age = %v)", pairs, ent.Age())

	data := ent.Bytes()
	if len(data) != 8 {
		return 0, false
	}

	val := binary.BigEndian.Uint64(data)
	return val, true
}

// saveRuleCache uses the cachable generic to serialize the rule data to disk
func (c *Censeye) saveRuleCache(pairs []components.FieldValuePair, count uint64) error {
	obj := &cache.GenericCachable[uint64]{
		Key:   fpkSet(pairs),
		Value: count,
		Enc: func(v uint64) []byte {
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, v)
			return buf
		},
	}

	_, err := c.cache.Save(obj)
	return err
}

// Hash returns a string hash for the fpkSet, used for the generic cache interface.
func (f fpkSet) Hash() string {
	parts := make([]string, len(f))
	for i, p := range f {
		if strings.HasPrefix(p.Value, "(") {
			parts[i] = fmt.Sprintf("%s:%s", p.Field, p.Value)
		} else {
			parts[i] = fmt.Sprintf("%s=%s", p.Field, p.Value)
		}
	}

	// sort it so we always have a consistent hash
	sort.Strings(parts)
	return strings.Join(parts, " and ")
}
