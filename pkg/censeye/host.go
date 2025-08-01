package censeye

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/censys/censys-sdk-go/models/components"
	"github.com/censys/censys-sdk-go/models/operations"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// getHost will take a host IP or hostname and return the full host asset (either from the cache, or from the API).c
func (c *Censeye) getHost(ctx context.Context, host string, opts *runOpts) (gjson.Result, error) {
	log.Debugf("Fetching host %s with atTime %v", host, opts.atTime)

	if res, ok := c.loadHostCache(host, opts.atTime); ok {
		log.Debugf("Loaded host %s from cache", host)
		return res, nil
	} else {
		log.Infof("Host %s not found in cache, fetching from Censys", host)
	}

	c.sendStatus(fmt.Sprintf("fetching data for: %s...", host))

	nres := gjson.Result{}

	res, err := c.client.GlobalData.GetHost(ctx,
		operations.V3GlobaldataAssetHostRequest{
			HostID: host,
			AtTime: opts.atTime,
		},
	)

	if err != nil {
		log.Warnf("Error fetching host %s: %v", host, err)
		return nres, err
	}

	hostres := res.GetResponseEnvelopeHostAsset().GetResult()
	if hostres == nil {
		return nres, fmt.Errorf("no host asset found for %s", host)
	}

	jstr, err := json.Marshal(hostres.GetResource())
	if err != nil {
		log.Warnf("Error marshalling host resource for %s: %v", host, err)
		return nres, fmt.Errorf("error marshalling host resource: %w", err)
	}

	parsed := gjson.ParseBytes(jstr)
	c.saveHostCache(host, opts.atTime, parsed)

	c.Lock()
	c.credits++
	c.Unlock()

	c.sendStatus(fmt.Sprintf("fetching data for: %s... [DONE!]", host))
	return parsed, nil
}

// getHosts will take a cenql query, and search for hosts that match it.
// it should be noted that currently the API will return all data associated
// with a host in a search response, which allows us to pre-cache the data. However,
// this may not be around in the future, so we first check to see if it has any
// services so this doesn't break.
func (c *Censeye) getHosts(ctx context.Context, search string) ([]string, error) {
	c.sendStatus(fmt.Sprintf("executing query: %s...", search))

	if val, ok := c.loadSearchCache(search); ok {
		log.Debugf("loaded %d hosts from search cache for query: %s", len(val), search)
		return val, nil
	}

	s := components.SearchQueryInputBody{
		// we can grab all the fields from a search request, which is cool, but i'm unsure
		// if this is a censys-employee-only thing or not.
		// Fields:    []string{"host.ip"},
		PageToken: nil,
		Query:     search,
	}

	req := operations.V3GlobaldataSearchQueryRequest{
		SearchQueryInputBody: s,
	}

	// we need to add a max pages sometime in the future...
	page := 0
	results := make([]string, 0)

	for {
		page++
		c.sendStatus(fmt.Sprintf("executing query: %s... [page %d]", search, page))

		res, err := c.client.GlobalData.Search(ctx, req)
		if err != nil {
			log.Warnf("Error searching for hosts with query %s: %v", search, err)
			return nil, fmt.Errorf("failed to search for hosts: %w", err)
		}

		result := res.GetResponseEnvelopeSearchQueryResponse().GetResult()

		for _, hit := range result.GetHits() {
			var ipstr string

			resource := hit.GetHostV1().GetResource()
			if ip := resource.GetIP(); ip != nil {
				results = append(results, *ip)
				ipstr = *ip
			}

			// what's interesting about the new api is  that our search results can not contain the full
			// host result. This means that we can pre-cache the host data so we don't have to dip in a
			// second time. But, only do this if there is more than one service, as it doesn't seem like
			// this was an intended use case.
			if len(resource.GetServices()) == 0 {
				continue
			}

			jstr, err := json.Marshal(resource)
			if err != nil {
				log.Warnf("Error marshalling host resource for search %s: %v", search, err)
				continue
			}

			// search results never have an atTime.
			log.Debugf("Saving host %s to cache from search %s", ipstr, search)
			c.saveHostCache(ipstr, nil, gjson.ParseBytes(jstr))
		}

		c.Lock()
		c.credits++
		c.Unlock()

		next := result.GetNextPageToken()
		req.SearchQueryInputBody.PageToken = &next

		if next == "" {
			break
		}
	}

	if err := c.saveSearchCache(search, results); err != nil {
		log.Warnf("Failed to save search cache for query %s: %v", search, err)
	}

	c.sendStatus(fmt.Sprintf("executing query: %s...DONE! found %d hosts", search, len(results)))

	return results, nil
}
