package censeye

import (
	"encoding/json"
	"fmt"

	"github.com/censys-research/censeye-ng/pkg/cache"
	"github.com/censys/censys-sdk-go/models/components"
)

type certHistoryKey struct {
	fingerprint string
	days        int
}

func (c certHistoryKey) Hash() string {
	return fmt.Sprintf("%s_%d", c.fingerprint, c.days)
}

// loadCertHistoryCache attempts to load the certificate history cache for a given fingerprint and day range
func (c *Censeye) loadCertHistoryCache(fingerprint string, days int) ([]components.HostObservationRange, bool) {
	obj := &cache.GenericCachable[[]components.HostObservationRange]{
		Key: certHistoryKey{fingerprint: fingerprint, days: days},
		Enc: func(_ []components.HostObservationRange) []byte { return nil }, // not used for load
	}

	entry, err := c.cache.Load(obj)
	if err != nil {
		return nil, false
	}

	var ret []components.HostObservationRange
	if err := json.Unmarshal(entry.Bytes(), &ret); err != nil {
		return nil, false
	}

	return ret, true
}

// saveCertHistoryCache uses the cachable generic to serialize the certificate history results to disk
func (c *Censeye) saveCertHistoryCache(fingerprint string, days int, observations []components.HostObservationRange) error {
	obj := &cache.GenericCachable[[]components.HostObservationRange]{
		Key:   certHistoryKey{fingerprint: fingerprint, days: days},
		Value: observations,
		Enc: func(obs []components.HostObservationRange) []byte {
			data, err := json.Marshal(obs)
			if err != nil {
				return nil
			}
			return data
		},
	}

	_, err := c.cache.Save(obj)
	return err
}
