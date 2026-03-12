package censeye

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/censys/censys-sdk-go/models/components"
	"github.com/censys/censys-sdk-go/models/operations"
	log "github.com/sirupsen/logrus"
)

func (c *Censeye) makeEntry(pairs []FieldValuePairLike, count uint64) *reportEntry {
	entry := &reportEntry{
		pairs:         pairs,
		Count:         int64(count),
		IsInteresting: c.config.Rarity.IsInteresting(count),
	}

	entry.SearchURL = entry.ToURL()
	entry.CenqlQuery = entry.ToCenqlQuery()
	return entry
}

type FVPLegacyType string

const (
	FVPLegacyTypeWildcard FVPLegacyType = "wildcard"
	FVPLegacyTypeRegex    FVPLegacyType = "regex"
)

type FVPLegacy struct {
	components.FieldValuePair
	Type FVPLegacyType
}

// GetField and GetValue implement FieldValuePairLike (value receiver so FVPLegacy implements the interface).
func (f FVPLegacy) GetField() string { return f.Field }
func (f FVPLegacy) GetValue() string { return f.Value }

// CenqlOperator implements FieldValuePairLike for regex (=~) vs wildcard/exact (=).
func (f FVPLegacy) CenqlOperator() string {
	if f.Type == FVPLegacyTypeRegex {
		return "=~"
	} else if f.Type == FVPLegacyTypeWildcard {
		return ":"
	}
	return "="
}

func (c *Censeye) GetCountsLegacy(ctx context.Context, host string, rules []FVPLegacy) (*Report, error) {
	if c.client == nil {
		return nil, fmt.Errorf("censeye is not initialized")
	}

	c.sendStatus(fmt.Sprintf("fetching value-counts (%d) for host %s...", len(rules), host))

	allCounts := make([]uint64, len(rules))

	for i, pair := range rules {
		logForHost(host).Debugf("rule: %s %s %s", pair.Type, pair.GetField(), pair.GetValue())

		op := ":"
		switch pair.Type {
		case FVPLegacyTypeWildcard:
			op = ":"
		case FVPLegacyTypeRegex:
			op = "=~"
		}

		q := fmt.Sprintf("%s%s`%s`", pair.GetField(), op, pair.GetValue())

		logForHost(host).Infof("query: %s", q)

		res, err := c.client.GlobalData.Aggregate(ctx, operations.V3GlobaldataSearchAggregateRequest{
			SearchAggregateInputBody: components.SearchAggregateInputBody{
				Field:           "host.ip", // TODO: we should also process web.endpoint.ip
				NumberOfBuckets: 1,         // we only need 1 to get total
				Query:           q,
			},
		})

		if err != nil {
			log.Warnf("Error fetching count for rule %v: %v", pair, err)
			allCounts[i] = 0
			continue
		}

		tot := res.GetResponseEnvelopeSearchAggregateResponse().GetResult().GetTotalCount()
		allCounts[i] = uint64(tot)

		if log.GetLevel() >= log.DebugLevel {
			j, _ := json.MarshalIndent(res, "", "  ")
			logForHost(host).Debugf("raw response: %s", string(j))
		}
	}

	// Build report entries using FieldValuePairLike (FVPLegacy implements it).
	entries := make([]*reportEntry, 0, len(rules))
	for i, count := range allCounts {
		pairs := []FieldValuePairLike{rules[i]}
		entries = append(entries, c.makeEntry(pairs, count))
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	c.sendStatus(fmt.Sprintf("fetched value-counts (%d) for host %s... DONE!", len(entries), host))

	return &Report{
		Host:    host,
		Data:    entries,
		Credits: len(rules),
	}, nil
}

func (c *Censeye) getCounts(ctx context.Context, host string, rules [][]components.FieldValuePair) (*Report, error) {
	if c.client == nil {
		return nil, fmt.Errorf("censeye is not initialized")
	}

	c.sendStatus(fmt.Sprintf("fetching value-counts (%d) for host %s...", len(rules), host))

	var (
		uncachedRules [][]components.FieldValuePair
		uncachedIndex []int
		allCounts     = make([]uint64, len(rules))
	)

	// split up our data into cached / uncached
	for i, rule := range rules {
		if val, ok := c.loadRuleCache(rule); ok {
			allCounts[i] = val
		} else {
			uncachedIndex = append(uncachedIndex, i)
			uncachedRules = append(uncachedRules, rule)
		}
	}

	logForHost(host).Infof("Found %d cached rules and %d uncached rules", len(rules)-len(uncachedRules), len(uncachedRules))

	srules := components.SearchValueCountsInputBody{
		AndCountConditions: make([]components.CountCondition, 0),
	}

	for _, rule := range uncachedRules {
		srule := components.CountCondition{
			FieldValuePairs: rule,
		}
		srules.AndCountConditions = append(srules.AndCountConditions, srule)
	}

	c.Lock()
	// one credit for every AndCountCondition we query.
	c.credits += len(uncachedRules)
	c.Unlock()

	// we should only query the rules that are not already cached.
	if len(uncachedRules) > 0 {
		cquery := operations.V3ThreathuntingValueCountsRequest{
			SearchValueCountsInputBody: srules,
		}

		if log.GetLevel() >= log.DebugLevel {
			jstr, _ := json.MarshalIndent(cquery, "", "  ")
			logForHost(host).Debugf("querying: %s", jstr)
		}

		ret, err := c.client.ThreatHunting.ValueCounts(ctx, cquery)
		if err != nil {
			return nil, fmt.Errorf("error getting value counts for host %s: %w", host, err)
		}

		resp := ret.GetResponseEnvelopeValueCountsResponse().GetResult().GetAndCountResults()

		for j, rawCount := range resp {
			i := uncachedIndex[j]
			count := uint64(rawCount)
			allCounts[i] = count

			if err := c.saveRuleCache(rules[i], count); err != nil {
				logForHost(host).Warnf("error saving cache for rule %v: %v", rules[i], err)
			}
		}
	}

	// we need to join our entries.
	entries := make([]*reportEntry, 0, len(rules))
	for i, count := range allCounts {
		pairs := make([]FieldValuePairLike, len(rules[i]))
		for j := range rules[i] {
			pairs[j] = stdFieldValuePair{rules[i][j]}
		}
		entries = append(entries, c.makeEntry(pairs, count))
	}

	// sort by count descending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	interestingCount := 0
	for _, entry := range entries {
		if entry.IsInteresting {
			interestingCount++
		}
	}

	c.sendStatus(fmt.Sprintf("fetched value-counts (%d) for host %s... DONE!", len(entries), host))

	return &Report{
		Host:    host,
		Data:    entries,
		Credits: len(uncachedRules),
	}, nil
}
