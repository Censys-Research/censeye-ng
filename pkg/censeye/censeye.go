package censeye

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/censys-research/censeye-ng/pkg/cache"
	"github.com/censys-research/censeye-ng/pkg/config"
	censys "github.com/censys/censys-sdk-go"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"golang.org/x/sync/errgroup"
)

const (
	hostPfx    = "host"
	defaultPfx = hostPfx
)

type runTask struct {
	host    string
	labels  []string
	threats []string
	ref     *Referrer
	depth   int
}

// New creates a new Censeye instance with the provided options.
func New(options ...Option) *Censeye {
	c := new(Censeye)

	for _, option := range options {
		option(c)
	}

	if c.config == nil {
		c.config = config.NewConfig()
	}

	if c.config.Workdir == "" {
		// should probably swap this over to XDG. but for now, we default to ~/.censeye for our caches.
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("could not get home directory: %v", err)
		}

		c.config.Workdir = filepath.Join(home, ".censeye")
	}

	c.cache = cache.NewManager(
		filepath.Join(c.config.Workdir, "cache"),
		c.config.CacheDuration,
	)

	return c
}

// WithConfig allows you to set a custom configuration for Censeye.
func WithConfig(cfg *config.Config) Option { return func(c *Censeye) { c.config = cfg } }

// WithClient sets the underlying Censys SDK client.
func WithClient(client *censys.SDK) Option {
	return func(c *Censeye) {
		c.client = client
	}
}

// WithStatusCallback allows you to set a callback function that will be called with various update messages (i.e., a logger/spinner)
func WithStatusCallback(callback func(message string)) Option {
	return func(c *Censeye) {
		c.statusCb = callback
	}
}

func (c *Censeye) sendStatus(message string) {
	if c.statusCb != nil {
		c.statusCb(message)
	}
}

// WithDepth sets the maximum depth for recursive pivoting
func WithDepth(depth int) RunOpt {
	return func(ro *runOpts) {
		ro.depth = depth
	}
}

func initRunState() *runState {
	return &runState{
		hostsChecked: make(map[string]bool),
		queryChecked: make(map[string]bool),
	}
}

// WithAtTime sets the date/time to use for historical queries.
func WithAtTime(atTime *time.Time) RunOpt {
	return func(ro *runOpts) {
		ro.atTime = atTime
	}
}

// Run starts the whole Censeye "process".
//  1. fetches the host information from the API (if not cached)
//  2. iterates over all of the results and generates legitimate CenQL queries for each
//  3. filtering is applied to the last-step's result to remove things we don't care about
//  4. service-specific queries are generated and added to the list of things to query.
//  5. a call is made to the GetCounts API for all of our compiled queries
//  6. an array of counts is returned, each count associated with a set of queries we made
//
// Then, if a depth is defined, and we're not at the max depth, we recursively run the process for
// each unique host found in the results that were tagged as "interesting" (e.g., the count was between
// the set threshold).
//
// The return of which is a slice of Reports, each containing the results of the queries made.
func (c *Censeye) Run(ctx context.Context, host string, opts ...RunOpt) ([]*Report, error) {
	return c.run(ctx, host, opts...)
}

// collectHosts will take a report and iterate over the entries of cenql queries. Those queries will then be run, and the
// hosts matching those queries will be returned.
// Note that search queries are cached for a period of time (default 24h)
func (c *Censeye) collectHosts(ctx context.Context, viahost string, rep *Report, ro *runOpts) map[string]*Referrer {
	c.sendStatus(fmt.Sprintf("collecting hosts using %d queries via %s", len(rep.Data), viahost))

	res := make(map[string]*Referrer)
	nqr := 0

	for _, entry := range rep.Data {
		ro.state.Lock()

		if !entry.IsInteresting || ro.state.queryChecked[entry.CenqlQuery] {
			ro.state.Unlock()
			continue
		}

		// check to see if our pivotable fields are set, and if so, whether this entry has any of those fields.
		// if it doesn't, we skip this entry.
		pivotable := c.config.GetPivotableFields()
		if len(pivotable) > 0 {
			log.Debugf("checking entry %s against pivotable fields: %v", entry.CenqlQuery, pivotable)
			hasfield := false

			for _, pair := range entry.Pairs {
				if slices.Contains(pivotable, pair.GetField()) {
					hasfield = true
					log.Debugf("entry %s contains pivotable field: %s", entry.CenqlQuery, pair.GetField())
					break
				}
			}

			// if we don't have any of the pivotable fields, skip this entry...
			if !hasfield {
				log.Debugf("skipping entry %s - no pivotable fields found", entry.CenqlQuery)
				ro.state.Unlock()
				continue
			}
		}

		ro.state.queryChecked[entry.CenqlQuery] = true
		ro.state.Unlock()
		nqr++

		log.Debugf("collecting hosts for: %s", entry.CenqlQuery)
		hosts, err := c.getHosts(ctx, entry.CenqlQuery)
		if err != nil {
			log.Warnf("error getting hosts for entry %s: %v", entry.CenqlQuery, err)
			continue
		}

		for _, h := range hosts {
			ro.state.Lock()
			if h != "" && !ro.state.hostsChecked[h] {
				if existingRef := res[h]; existingRef != nil {
					// host already found by another query, append this query to the Via slice
					existingRef.Via = append(existingRef.Via, entry)
				} else {
					// new host, create new referrer with this query
					res[h] = &Referrer{viahost, []*reportEntry{entry}}
				}
			}
			ro.state.Unlock()
		}
	}

	log.Infof("collected %d unique hosts from %d queries", len(res), nqr)
	c.sendStatus(fmt.Sprintf("collected %d unique hosts from %d queries", len(res), nqr))

	return res
}

func (c *Censeye) runPivots(
	ctx context.Context,
	task runTask,
	ro *runOpts,
) ([]*Report, map[string]*Referrer, error) {
	res, err := c.getHost(ctx, task.host, ro)
	if err != nil {
		return nil, nil, err
	}

	// since we're here and have the host data, let's pull out relevant data we want to keep around
	task.labels, task.threats = c.getLabelsAndThreats(res)

	// generate the rules we will use to send over to the value-counts api
	rules, err := c.compileRules(res)
	if err != nil {
		return nil, nil, err
	}

	if log.GetLevel() >= log.DebugLevel {
		logForHost(task.host).Debugf("compiled %d rules for host %s", len(rules), task.host)
		j, _ := json.MarshalIndent(rules, "", "  ")
		logForHost(task.host).Debugf("rules: %s", j)
	}

	// now grab the data from the value-counts api using our compiled rules
	report, err := c.getCounts(ctx, task.host, rules)
	if err != nil {
		return nil, nil, err
	}

	report.Depth = task.depth
	report.Referrer = task.ref
	report.Labels = task.labels
	report.AtTime = ro.atTime
	report.Threats = task.threats
	reports := []*Report{report}

	var next map[string]*Referrer
	if task.depth < ro.depth {
		next = c.collectHosts(ctx, task.host, report, ro)
	}

	ro.state.Lock() // technically safe without, but just in case for future...
	ro.state.hostsChecked[task.host] = true
	ro.state.Unlock()

	return reports, next, nil
}

// run is the core engine behind Censeye's recursive pivot logic.
// it starts with a single host and walks outward by:
//  1. calling getHost() to fetch and cache host data
//  2. compiling rules from that data with compileRules()
//  3. executing those rules using getCounts(), which returns a report of matched query counts
//  4. passing that report into collectHosts(), which runs the matching CenQL queries
//     and returns new hosts that met the "interesting" criteria
//
// for each new host found, a runTask is scheduled, and this continues recursively up to the configured depth.
// all of this happens in parallel, bounded by a semaphore (configured via config.Workers).
// visited hosts and queries are tracked inside runState to prevent duplicates.
// each host and its associated report are logged and stored in the final results list.
func (c *Censeye) run(ctx context.Context, startHost string, opts ...RunOpt) ([]*Report, error) {
	ro := &runOpts{}
	for _, opt := range opts {
		opt(ro)
	}

	if ro.state == nil {
		ro.state = initRunState()
	}

	var (
		reports []*Report
		mu      sync.Mutex
		queue   = []runTask{{host: startHost, labels: nil, threats: nil, ref: nil, depth: 0}}
		sem     = make(chan struct{}, c.config.Workers)
	)

	// we only want to set the atTime for the first run, because the idea is that we
	// get a historical host, pull its fields, then run censeye on _current_ data to find
	// similar hosts now.
	doneFirst := false

	for len(queue) > 0 {
		var (
			nextQueue []runTask
			grp, gctx = errgroup.WithContext(ctx)
		)

		for _, task := range queue {
			ro.state.Lock()
			if ro.state.hostsChecked[task.host] {
				ro.state.Unlock()
				continue
			}
			ro.state.Unlock()

			// make a copy of the task.
			task := task
			sem <- struct{}{}
			grp.Go(func() error {
				defer func() {
					<-sem // release the sem
				}()

				return c.runTask(gctx, task, ro, &reports, &nextQueue, &mu)
			})
		}

		if err := grp.Wait(); err != nil {
			log.Warnf("errors in batch: %v", err)
		}

		queue = nextQueue

		if !doneFirst {
			ro.atTime = nil
			doneFirst = true
		}
	}

	return reports, nil
}

func (c *Censeye) runTask(
	ctx context.Context,
	task runTask,
	ro *runOpts,
	reports *[]*Report,
	nextQueue *[]runTask,
	mu *sync.Mutex,
) error {
	logForHost(task.host).Debugf("Processing at depth %d", task.depth)

	result, newHosts, err := c.runPivots(ctx, task, ro)
	if err != nil {
		logForHost(task.host).Warnf("error running censeye: %v", err)
		return nil
	}

	mu.Lock()
	defer mu.Unlock()

	*reports = append(*reports, result...)

	if task.depth+1 <= ro.depth {
		for h, ref := range newHosts {
			ro.state.Lock()
			if !ro.state.hostsChecked[h] {
				*nextQueue = append(*nextQueue, runTask{host: h, labels: nil, threats: nil, ref: ref, depth: task.depth + 1})
			}
			ro.state.Unlock()
		}
	}

	return nil
}

func (c *Censeye) getLabelsAndThreats(res gjson.Result) ([]string, []string) {
	uniq := func(items gjson.Result, field string) map[string]struct{} {
		out := make(map[string]struct{})
		if items.Exists() && items.IsArray() {
			for _, item := range items.Array() {
				if val := item.Get(field); val.Exists() && val.Type == gjson.String {
					out[val.String()] = struct{}{}
				}
			}
		}
		return out
	}

	labels := make(map[string]struct{})
	threats := make(map[string]struct{})

	if services := res.Get("services"); services.Exists() && services.IsArray() {
		for _, service := range services.Array() {
			maps.Copy(labels, uniq(service.Get("labels"), "value"))
			maps.Copy(threats, uniq(service.Get("threats"), "name"))
		}
	}

	toSlice := func(m map[string]struct{}) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		return out
	}

	return toSlice(labels), toSlice(threats)
}

// GetCredits returns the number of credits that have been used so far by this Censeye instance.
func (c *Censeye) GetCredits() int {
	c.Lock()
	defer c.Unlock()
	return c.credits
}

func init() {
	log.SetLevel(log.ErrorLevel)
}
