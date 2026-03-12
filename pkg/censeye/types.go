package censeye

import (
	"context"
	"encoding/json"
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

// LLMRegexExtractor is implemented by clients that can extract re2 regex patterns from an HTTP body (e.g. for analyze-html).
type LLMRegexExtractor interface {
	RunExtractRegexFromBody(ctx context.Context, body string) ([]string, error)
}

// StatusCallback is a simple callback that receives status update strings
type StatusCallback func(message string)

// Censeye is the main struct that holds the configuration, client, cache, credits, and a status callback.
type Censeye struct {
	sync.Mutex
	config    *config.Config
	client    *censys.SDK
	cache     *cache.Manager
	credits   int
	statusCb  StatusCallback
	llmClient LLMRegexExtractor
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

// Referrer is a structure that holds information about how we arrived at the current report
type Referrer struct {
	Host string         `json:"host"`
	Via  []*reportEntry `json:"via"`
}

// FieldValuePairLike is an interface for key-value pairs used in report entries.
// It allows both the SDK's FieldValuePair and legacy/wrapper types (e.g. regex)
// to be used when building CenQL queries and URLs. CenqlOperator() controls the
// operator in the output (e.g. "=" for exact/wildcard, "=~" for regex).
type FieldValuePairLike interface {
	GetField() string
	GetValue() string
	CenqlOperator() string // "=" for exact/wildcard, "=~" for regex
}

// stdFieldValuePair adapts components.FieldValuePair to FieldValuePairLike with operator "=".
type stdFieldValuePair struct {
	components.FieldValuePair
}

func (s stdFieldValuePair) GetField() string   { return s.Field }
func (s stdFieldValuePair) GetValue() string   { return s.Value }
func (s stdFieldValuePair) CenqlOperator() string { return "=" }

type reportEntry struct {
	pairs         []FieldValuePairLike
	Count         int64  `json:"count"`
	SearchURL     string `json:"search_url,omitempty"`
	CenqlQuery    string `json:"cenql_query,omitempty"`
	IsInteresting bool  `json:"is_interesting"`
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
	if r == nil || len(r.pairs) == 0 {
		return nil
	}
	out := make([]components.FieldValuePair, len(r.pairs))
	for i, p := range r.pairs {
		out[i] = components.FieldValuePair{Field: p.GetField(), Value: p.GetValue()}
	}
	return out
}

// MarshalJSON implements json.Marshaler so kv_pairs is emitted as [{"field","value"},...].
func (r *reportEntry) MarshalJSON() ([]byte, error) {
	type pairJSON struct {
		Field string `json:"field"`
		Value string `json:"value"`
	}
	kv := make([]pairJSON, len(r.pairs))
	for i, p := range r.pairs {
		kv[i] = pairJSON{Field: p.GetField(), Value: p.GetValue()}
	}
	return json.Marshal(struct {
		KvPairs        []pairJSON `json:"kv_pairs"`
		Count          int64      `json:"count"`
		SearchURL      string     `json:"search_url,omitempty"`
		CenqlQuery     string     `json:"cenql_query,omitempty"`
		IsInteresting  bool       `json:"is_interesting"`
	}{kv, r.Count, r.SearchURL, r.CenqlQuery, r.IsInteresting})
}

func (r *reportEntry) GetSearchURL() string {
	if r == nil {
		return ""
	}
	return r.SearchURL
}

// ToCenqlShort converts the report entry to a (raw) CenQL query format (non-urlized) with a shortened (non-standard) output.
func (r *reportEntry) ToCenqlShort() (string, string, int64) {
	if len(r.pairs) == 0 {
		return "", "", 0
	}

	if len(r.pairs) == 1 {
		p := r.pairs[0]
		return p.GetField(), p.CenqlOperator() + " " + fmt.Sprintf("%q", p.GetValue()), r.Count
	}

	splitf := make([][]string, len(r.pairs))
	for i, pair := range r.pairs {
		splitf[i] = strings.Split(pair.GetField(), ".")
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

	// now build out the field op val with the prefix removed...
	out := make([]string, len(r.pairs))
	for i, pair := range r.pairs {
		field := pair.GetField()
		if pfx != "" {
			field = strings.TrimPrefix(pair.GetField(), pfx+".")
		}
		out[i] = fmt.Sprintf("%s %s %q", field, pair.CenqlOperator(), pair.GetValue())
	}

	return pfx, fmt.Sprintf("(%s)", strings.Join(out, " and ")), r.Count
}

// ToCenql converts the report entry to a (raw) CenQL query format (non-urlized).
// For a single pair, v is "op \"value\"" so the full query is field + " " + v.
func (r *reportEntry) ToCenql() (string, string, int64) {
	if len(r.pairs) == 0 {
		return "", "", 0
	}

	const pfx = "host.services"

	if len(r.pairs) == 1 {
		p := r.pairs[0]
		v := p.CenqlOperator() + " " + fmt.Sprintf("%q", p.GetValue())
		return p.GetField(), v, r.Count
	}

	out := make([]string, len(r.pairs))
	for i, pair := range r.pairs {
		field := strings.TrimPrefix(pair.GetField(), pfx+".")
		out[i] = fmt.Sprintf("%s %s %q", field, pair.CenqlOperator(), pair.GetValue())
	}

	return pfx, fmt.Sprintf("(%s)", strings.Join(out, " and ")), r.Count
}

func (r *reportEntry) ToCenqlQuery() string {
	k, v, _ := r.ToCenql()
	if !strings.HasPrefix(v, "(") {
		return k + " " + v
	}
	return fmt.Sprintf("%s:%s", k, v)
}

func (r *reportEntry) GetIsInteresting() bool {
	if r == nil {
		return false
	}
	return r.IsInteresting
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
