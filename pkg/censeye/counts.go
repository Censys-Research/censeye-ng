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

func (c *Censeye) makeEntry(pairs []components.FieldValuePair, count uint64) *reportEntry {
	entry := &reportEntry{
		Pairs:         pairs,
		Count:         int64(count),
		IsInteresting: c.config.Rarity.IsInteresting(count),
	}

	entry.SearchURL = entry.ToURL()
	entry.CenqlQuery = entry.ToCenqlQuery()
	return entry
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
		entries = append(entries, c.makeEntry(rules[i], count))
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
