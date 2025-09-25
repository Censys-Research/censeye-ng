package censeye

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/censys-research/censeye-ng/pkg/cache"
	"github.com/censys-research/censeye-ng/pkg/config"
	censys "github.com/censys/censys-sdk-go"
	"github.com/censys/censys-sdk-go/models/components"
)

type Option func(*Censeye)
type RunOpt func(*runOpts)

// StatusCallback is a simple callback that receives status update strings
type StatusCallback func(message string)

// Censeye is the main struct that holds the configuration, client, cache, credits, and a status callback.
type Censeye struct {
	sync.Mutex
	config   *config.Config
	client   *censys.SDK
	cache    *cache.Manager
	credits  int
	statusCb StatusCallback
}

type runState struct {
	hostsChecked map[string]bool
	queryChecked map[string]bool
	sync.Mutex
}

type runOpts struct {
	depth  int
	atTime *time.Time
	via    *Referrer
	state  *runState
}

// Report is the public report structure that holds the results of a Censeye run.
type Report struct {
	Host     string         `json:"host"`
	AtTime   *time.Time     `json:"at_time,omitempty"`
	Credits  int            `json:"credits_used"`
	Referrer *Referrer      `json:"referrer,omitempty"`
	Depth    int            `json:"depth"`
	Labels   []string       `json:"labels"`
	Threats  []string       `json:"threats"`
	Data     []*reportEntry `json:"data"`
}

// MultiIPReport represents the results of analyzing multiple IPs for common attributes
type MultiIPReport struct {
	Hosts         []string                `json:"hosts"`
	AtTime        *time.Time              `json:"at_time,omitempty"`
	Credits       int                     `json:"credits_used"`
	CommonAttribs []*commonAttributeEntry `json:"common_attributes"`
	HostCount     int                     `json:"host_count"`
}

// commonAttributeEntry represents an attribute common to multiple hosts in the set
type commonAttributeEntry struct {
	Pairs         []components.FieldValuePair `json:"kv_pairs"`
	HostSetCount  int                         `json:"host_set_count"` // how many hosts in the input set have this attribute
	TotalCount    int64                       `json:"total_count"`    // total count in Censys dataset
	SearchURL     string                      `json:"search_url,omitempty"`
	CenqlQuery    string                      `json:"cenql_query,omitempty"`
	IsInteresting bool                        `json:"is_interesting"`
}

// Referrer is a structure that holds information about how we arrived at the current report
type Referrer struct {
	Host string         `json:"host"`
	Via  []*reportEntry `json:"via"`
}

type reportEntry struct {
	Pairs         []components.FieldValuePair `json:"kv_pairs"`
	Count         int64                       `json:"count"`
	SearchURL     string                      `json:"search_url,omitempty"`
	CenqlQuery    string                      `json:"cenql_query,omitempty"`
	IsInteresting bool                        `json:"is_interesting"`
	// For multi-IP reports: how many hosts in the input set have this attribute
	HostSetCount int `json:"host_set_count,omitempty"`
}

func (r *Report) GetReferrer() *Referrer {
	if r == nil {
		return nil
	}
	return r.Referrer
}

func (r *Report) GetDepth() int {
	if r == nil {
		return 0
	}
	return r.Depth
}

func (r *Report) GetData() []*reportEntry {
	if r == nil {
		return nil
	}
	return r.Data
}

func (r *Report) GetHost() string {
	if r == nil {
		return ""
	}
	return r.Host
}

func (r *Referrer) GetVia() *reportEntry {
	if r == nil || len(r.Via) == 0 {
		return nil
	}
	return r.Via[0]
}

func (r *Referrer) GetAllVia() []*reportEntry {
	if r == nil {
		return nil
	}
	return r.Via
}

func (r *Referrer) GetHost() string {
	if r == nil {
		return ""
	}
	return r.Host
}

func (r *reportEntry) GetCount() int64 {
	if r == nil {
		return 0
	}
	return r.Count
}

func (r *reportEntry) GetCenqlQuery() string {
	if r == nil {
		return ""
	}
	return r.CenqlQuery
}

func (r *reportEntry) GetPairs() []components.FieldValuePair {
	if r == nil {
		return nil
	}
	return r.Pairs
}

func (r *reportEntry) GetSearchURL() string {
	if r == nil {
		return ""
	}
	return r.SearchURL
}

// ToCenqlShort converts the report entry to a (raw) CenQL query format (non-urlized) with a shortened (non-standard) output.
func (r *reportEntry) ToCenqlShort() (string, string, int64) {
	if len(r.Pairs) == 0 {
		return "", "", 0
	}

	if len(r.Pairs) == 1 {
		return r.Pairs[0].Field, fmt.Sprintf("%q", r.Pairs[0].Value), r.Count
	}

	splitf := make([][]string, len(r.Pairs))
	for i, pair := range r.Pairs {
		splitf[i] = strings.Split(pair.Field, ".")
	}

	// now find the longest common prefix...
	pfxp := splitf[0]

	for i := 1; i < len(splitf); i++ {
		j := 0

		for j < len(pfxp) && j < len(splitf[i]) && pfxp[j] == splitf[i][j] {
			j++
		}

		pfxp = pfxp[:j]

		if len(pfxp) == 0 {
			break
		}
	}

	pfx := strings.Join(pfxp, ".")

	// now build out the field=val with the prefix removed...
	out := make([]string, len(r.Pairs))
	for i, pair := range r.Pairs {
		field := pair.Field
		if pfx != "" {
			field = strings.TrimPrefix(pair.Field, pfx+".")
		}
		out[i] = fmt.Sprintf("%s=%q", field, pair.Value)
	}

	return pfx, fmt.Sprintf("(%s)", strings.Join(out, " and ")), r.Count
}

// ToCenql converts the report entry to a (raw) CenQL query format (non-urlized)
func (r *reportEntry) ToCenql() (string, string, int64) {
	if len(r.Pairs) == 0 {
		return "", "", 0
	}

	const pfx = "host.services"

	if len(r.Pairs) == 1 {
		return r.Pairs[0].Field, fmt.Sprintf("%q", r.Pairs[0].Value), r.Count
	}

	out := make([]string, len(r.Pairs))
	for i, pair := range r.Pairs {
		field := strings.TrimPrefix(pair.Field, pfx+".")
		out[i] = fmt.Sprintf("%s=%q", field, pair.Value)
	}

	return pfx, fmt.Sprintf("(%s)", strings.Join(out, " and ")), r.Count
}

func (r *reportEntry) ToCenqlQuery() string {
	k, v, _ := r.ToCenql()
	if !strings.HasPrefix(v, "(") {
		return fmt.Sprintf("%s=%s", k, v)
	}

	return fmt.Sprintf("%s:%s", k, v)
}

func (r *reportEntry) GetIsInteresting() bool {
	if r == nil {
		return false
	}
	return r.IsInteresting
}

func (r *reportEntry) GetHostSetCount() int {
	if r == nil {
		return 0
	}
	return r.HostSetCount
}

// ToURL converts the report entry to a URL that can be used to search on Censys
func (r *reportEntry) ToURL() string {
	return fmt.Sprintf("https://platform.censys.io/search?q=%s", url.QueryEscape(r.ToCenqlQuery()))
}

func (r *Referrer) String() string {
	if r == nil {
		return ""
	}
	if len(r.Via) == 0 {
		return fmt.Sprintf("via %s", r.Host)
	}
	if len(r.Via) == 1 {
		return fmt.Sprintf("%s (%s)", r.Host, r.Via[0].ToCenqlQuery())
	}
	return fmt.Sprintf("%s (%d queries)", r.Host, len(r.Via))
}

// Helper methods for commonAttributeEntry
func (c *commonAttributeEntry) GetHostSetCount() int {
	if c == nil {
		return 0
	}
	return c.HostSetCount
}

func (c *commonAttributeEntry) GetTotalCount() int64 {
	if c == nil {
		return 0
	}
	return c.TotalCount
}

func (c *commonAttributeEntry) GetCenqlQuery() string {
	if c == nil {
		return ""
	}
	return c.CenqlQuery
}

func (c *commonAttributeEntry) GetPairs() []components.FieldValuePair {
	if c == nil {
		return nil
	}
	return c.Pairs
}

func (c *commonAttributeEntry) GetSearchURL() string {
	if c == nil {
		return ""
	}
	return c.SearchURL
}

func (c *commonAttributeEntry) GetIsInteresting() bool {
	if c == nil {
		return false
	}
	return c.IsInteresting
}

// ToCenqlShort converts the common attribute entry to a (raw) CenQL query format (non-urlized) with a shortened output.
func (c *commonAttributeEntry) ToCenqlShort() (string, string, int, int64) {
	if len(c.Pairs) == 0 {
		return "", "", 0, 0
	}

	if len(c.Pairs) == 1 {
		return c.Pairs[0].Field, fmt.Sprintf("%q", c.Pairs[0].Value), c.HostSetCount, c.TotalCount
	}

	splitf := make([][]string, len(c.Pairs))
	for i, pair := range c.Pairs {
		splitf[i] = strings.Split(pair.Field, ".")
	}

	// find the longest common prefix
	pfxp := splitf[0]
	for i := 1; i < len(splitf); i++ {
		j := 0
		for j < len(pfxp) && j < len(splitf[i]) && pfxp[j] == splitf[i][j] {
			j++
		}
		pfxp = pfxp[:j]
		if len(pfxp) == 0 {
			break
		}
	}

	pfx := strings.Join(pfxp, ".")

	// build out the field=val with the prefix removed
	out := make([]string, len(c.Pairs))
	for i, pair := range c.Pairs {
		field := pair.Field
		if pfx != "" {
			field = strings.TrimPrefix(pair.Field, pfx+".")
		}
		out[i] = fmt.Sprintf("%s=%q", field, pair.Value)
	}

	return pfx, fmt.Sprintf("(%s)", strings.Join(out, " and ")), c.HostSetCount, c.TotalCount
}

// ToCenqlQuery converts the common attribute entry to a CenQL query format
func (c *commonAttributeEntry) ToCenqlQuery() string {
	k, v, _, _ := c.ToCenqlShort()
	if !strings.HasPrefix(v, "(") {
		return fmt.Sprintf("%s=%s", k, v)
	}
	return fmt.Sprintf("%s:%s", k, v)
}

// ToURL converts the common attribute entry to a URL that can be used to search on Censys
func (c *commonAttributeEntry) ToURL() string {
	return fmt.Sprintf("https://platform.censys.io/search?q=%s", url.QueryEscape(c.ToCenqlQuery()))
}
