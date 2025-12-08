package censeye

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/censys/censys-sdk-go/models/components"
	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/savioxavier/termlink"
	"github.com/xlab/treeprint"
	"golang.org/x/term"
)

// Reporter is responsible for generating and printing reports (pivot-trees, tables, etc.)
type Reporter struct {
	w         io.Writer
	useColor  bool
	useLinks  bool
	colors    TableColors
	termWidth int
}

// TableColors defines the color styles used in the reporter
type TableColors struct {
	Count     color.Style
	Key       color.Style
	Val       color.Style
	CountBold color.Style
	KeyBold   color.Style
	ValBold   color.Style
}

type iPivot struct {
	searchURL  string
	cenqlQuery string
	count      int64
}

// NewReporter creates a new Reporter instance with the specified writer and optional flags
func NewReporter(w io.Writer, args ...string) *Reporter {
	flags := map[string]bool{}
	for _, arg := range args {
		flags[arg] = true
	}

	isTTY := false
	width := 200
	if f, ok := w.(*os.File); ok {
		fd := f.Fd()
		isTTY = term.IsTerminal(int(fd))
		if isTTY {
			if w, _, err := term.GetSize(int(fd)); err == nil {
				width = w
			}
		}
	}

	useColor := (color.SupportColor() && isTTY) && !flags["no-colors"]
	useLinks := (termlink.SupportsHyperlinks() && isTTY) && !flags["no-links"]

	st := func(fg color.Color, bold bool) color.Style {
		if bold {
			return color.New(fg, color.OpBold)
		}
		return color.New(fg)
	}

	return &Reporter{
		w:         w,
		useColor:  useColor,
		useLinks:  useLinks,
		termWidth: width,
		colors: TableColors{
			Count:     st(color.FgDefault, false),
			Key:       st(color.FgCyan, false),
			Val:       st(color.FgGreen, false),
			CountBold: st(color.FgDefault, true),
			KeyBold:   st(color.FgCyan, true),
			ValBold:   st(color.FgGreen, true),
		},
	}
}

func (r *Reporter) linkHost(ip string) string {
	return r.linkHostWithTime(ip, nil)
}

func (r *Reporter) linkHostWithTime(ip string, atTime *time.Time) string {
	if !r.useLinks {
		return ip
	}

	if atTime != nil {
		return termlink.Link(ip, fmt.Sprintf("https://platform.censys.io/hosts/%s?at_time=%s",
			url.QueryEscape(ip), url.QueryEscape(atTime.Format(time.RFC3339Nano))))
	}

	return termlink.Link(ip, fmt.Sprintf("https://platform.censys.io/hosts/%s", url.QueryEscape(ip)))
}

func (r *Reporter) linkQuery(q string) string {
	if !r.useLinks {
		return q
	}

	qorig := q

	if r.termWidth < 50 {
		if len(q) > 20 {
			return q[:20] + "..."
		}
		return q
	}

	maxLen := int(max(float64(r.termWidth-50), 0))
	if len(q) > maxLen {
		q = q[:maxLen] + "..."
	}

	return fmt.Sprintf("%s %s",
		termlink.Link("⮺",
			fmt.Sprintf("https://platform.censys.io/search?q=%s", url.QueryEscape(qorig))), q)
}

func (r *Reporter) colorize(entry *reportEntry, key, val, count string) (string, string, string) {
	if !r.useColor {
		if entry.IsInteresting {
			return fmt.Sprintf("*%s*", count), key, val
		}
		return count, key, val
	}

	if entry.IsInteresting {
		return r.colors.CountBold.Render(count), r.colors.KeyBold.Render(key), r.colors.ValBold.Render(val)
	}

	return r.colors.Count.Render(count), r.colors.Key.Render(key), r.colors.Val.Render(val)
}

// formatTags formats a slice of strings as a compact tag display
func (r *Reporter) formatTags(tags []string, tagType string) string {
	if len(tags) == 0 {
		return ""
	}

	// Color the tags based on type
	var colorStyle color.Style
	if r.useColor {
		if tagType == "threats" {
			colorStyle = color.New(color.FgRed, color.OpBold)
		} else {
			colorStyle = color.New(color.FgYellow)
		}
	}

	formatted := make([]string, len(tags))
	for i, tag := range tags {
		if r.useColor {
			formatted[i] = colorStyle.Render(tag)
		} else {
			formatted[i] = tag
		}
	}

	return fmt.Sprintf(" %s:[%s]", tagType, strings.Join(formatted, ","))
}

// formatHostWithTags formats a host with its labels and threats
func (r *Reporter) formatHostWithTags(host string, labels, threats []string) string {
	result := host
	if len(labels) > 0 {
		result += r.formatTags(labels, "labels")
	}
	if len(threats) > 0 {
		result += r.formatTags(threats, "threats")
	}
	return result
}

// formatViaQuery formats a via query with hyperlink and color
func (r *Reporter) formatViaQuery(query string) string {
	if !r.useLinks && !r.useColor {
		return query
	}

	// First create the hyperlink
	linked := r.linkQuery(query)

	// If colors are enabled, colorize just the query part (not the hyperlink symbol)
	if r.useColor {
		viaColor := color.New(color.FgCyan)

		// If there's a hyperlink, we need to be careful not to color the link symbol
		if r.useLinks && strings.Contains(linked, "⮺") {
			// Split on the hyperlink symbol and colorize only the query part
			parts := strings.SplitN(linked, " ", 2)
			if len(parts) == 2 {
				return parts[0] + " " + viaColor.Render(parts[1])
			}
		}
		// If no hyperlink, just colorize the whole thing
		return viaColor.Render(linked)
	}

	return linked
}

// PivotTree generates a pivot tree from the provided reports
func (r *Reporter) PivotTree(reports []*Report) {
	pivotNodes := r.CreatePivotTree(reports)
	if len(pivotNodes) == 0 {
		return
	}

	fmt.Fprintln(r.w, "\nPivot Tree:")
	for _, root := range pivotNodes {
		tree := treeprint.New()
		host := r.linkHostWithTime(root.IP, root.AtTime)
		hostWithTags := r.formatHostWithTags(host, root.Labels, root.Threats)

		// Add at_time display if present
		rootLabel := fmt.Sprintf("%s (depth %d)", hostWithTags, root.Depth)
		if root.AtTime != nil {
			rootLabel = fmt.Sprintf("%s @ %s (depth %d)", hostWithTags, root.AtTime.Format(time.RFC3339), root.Depth)
		}

		tree.SetValue(rootLabel)

		r.buildTreeFromNodes(tree, root.Children)
		fmt.Fprintln(r.w, tree.String())
	}
}

func (r *Reporter) buildTreeFromNodes(t treeprint.Tree, nodes []*PivotNode) {
	if len(nodes) == 0 {
		return
	}

	for _, node := range nodes {
		if node.Via != "" {
			// This is a "via" grouping node
			formattedQuery := r.formatViaQuery(node.Via)
			label := fmt.Sprintf("via: %s", formattedQuery)
			viaBranch := t.AddBranch(label)
			r.buildTreeFromNodes(viaBranch, node.Children)
		} else {
			// This is an IP node with optional at_time
			host := r.linkHostWithTime(node.IP, node.AtTime)
			hostWithTags := r.formatHostWithTags(host, node.Labels, node.Threats)

			// Add at_time display if present
			if node.AtTime != nil {
				hostWithTags = fmt.Sprintf("%s @ %s", hostWithTags, node.AtTime.Format(time.RFC3339))
			}

			branch := t.AddBranch(hostWithTags)
			r.buildTreeFromNodes(branch, node.Children)
		}
	}
}

// Tables generates and prints tables for multiple reports
func (r *Reporter) Tables(reports []*Report) {
	for _, report := range reports {
		r.Table(report)
	}
}

// Table generates a table for a single report using the configured color/hyperlink settings
func (r *Reporter) Table(report *Report) {
	t := table.NewWriter()
	t.SetStyle(table.Style{
		Box: table.BoxStyle{
			PaddingLeft:      " ",
			PaddingRight:     " ",
			UnfinishedRow:    " ",
			TopSeparator:     "─",
			MiddleHorizontal: "─",
		},
		Format: table.FormatOptions{
			Row: text.FormatDefault,
		}, Options: table.Options{
			DrawBorder:      false,
			SeparateColumns: true,
			SeparateFooter:  false,
			SeparateHeader:  true,
			SeparateRows:    false,
		},
	})
	t.SetOutputMirror(r.w)

	if r.useLinks {
		t.AppendHeader(table.Row{"🔗", "Hosts", "Key", "Val"})
	} else {
		t.AppendHeader(table.Row{"Hosts", "Key", "Val"})
	}

	wid := r.termWidth
	t.AppendSeparator()

	hcol := 10
	maxKeyLen := 0
	for _, entry := range report.GetData() {
		key, _, _ := entry.ToCenqlShort()
		key = strings.TrimPrefix(key, "host.services.")
		key = strings.TrimPrefix(key, "endpoints.")
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
	}

	keyColWidth := maxKeyLen + 4
	valColWidth := wid - hcol - keyColWidth - 10
	valColWidth = max(valColWidth, 20)

	for _, entry := range report.GetData() {
		key, val, count := entry.ToCenqlShort()
		key = strings.TrimPrefix(key, "host.services.")
		key = strings.TrimPrefix(key, "endpoints.")
		cfmt, key, val := r.colorize(entry, key, val, strconv.FormatInt(count, 10))

		if r.useLinks {
			t.AppendRow(table.Row{
				termlink.Link("⮺", entry.GetSearchURL()),
				cfmt,
				key,
				text.WrapText(val, valColWidth),
			})
		} else {
			t.AppendRow(table.Row{
				cfmt,
				key,
				text.WrapText(val, valColWidth),
			})
		}
	}

	host := report.GetHost()
	viah := report.GetReferrer().GetHost()
	viaq := report.GetReferrer().GetVia().GetCenqlQuery()
	vial := report.GetReferrer().GetVia().GetSearchURL()
	via := viaq

	if r.useLinks {
		via = termlink.Link(viaq, vial)

		// Link parent host (no at_time for parent)
		viah = r.linkHost(viah)

		// Link current host with its at_time if present
		host = r.linkHostWithTime(host, report.AtTime)
	}

	var allVia string

	for _, viaEntry := range report.GetReferrer().GetAllVia() {
		allVia += viaEntry.GetCenqlQuery() + ", "
	}

	hostWithTags := r.formatHostWithTags(host, report.Labels, report.Threats)

	// Add at_time to the header if present
	atTimeStr := ""
	if report.AtTime != nil {
		atTimeStr = fmt.Sprintf(" at_time=%s", report.AtTime.Format(time.RFC3339Nano))
	}

	fmt.Fprintf(r.w, "\n%s (depth: %d) (via: %s -- %s)%s\n", hostWithTags, report.GetDepth(), viah, via, atTimeStr)

	if report.GetReferrer() != nil {
		fmt.Fprintf(r.w, "Parent IP: %s\n", viah)
		fmt.Fprintln(r.w, "All matching queries:")
		for _, viaEntry := range report.GetReferrer().GetAllVia() {
			fmt.Fprintf(r.w, " - %s\n", r.formatViaQuery(viaEntry.GetCenqlQuery()))
		}
	}

	t.Render()

	// Display historical certificate observations if any
	r.HistoricalCertificateObservations(report)
}

// HistoricalCertificateObservations displays historical certificate observations in a tree format
func (r *Reporter) HistoricalCertificateObservations(report *Report) {
	// Collect all historical observations from the report
	histObs := make(map[string][]components.HostObservationRange)

	for _, entry := range report.GetData() {
		if len(entry.HistoricalObservations) > 0 {
			// Create a key like "host.services.cert.fingerprint_sha256=abc123"
			key, val, _ := entry.ToCenql()
			if !strings.HasPrefix(val, "(") {
				histKey := fmt.Sprintf("%s=%s", key, val)
				histObs[histKey] = entry.HistoricalObservations
			}
		}
	}

	if len(histObs) == 0 {
		return
	}

	// First pass: filter certificates to only those with valid observations
	validHistObs := make(map[string]map[string][]string) // certKey -> ipToTimes

	for certKey, observations := range histObs {
		ipToTimes := make(map[string][]string)

		for _, obs := range observations {
			ip := obs.GetIP()
			if ip == "" {
				continue
			}

			// Skip if this is the current host we're analyzing
			if ip == report.GetHost() {
				continue
			}

			// Collect timestamps for this IP
			startTime := obs.GetStartTime()
			endTime := obs.GetEndTime()

			// Format timestamps to RFC3339Nano (e.g., 2025-11-11T11:22:29.622899241Z)
			var startStr, endStr string

			if !startTime.IsZero() {
				startStr = startTime.Format(time.RFC3339Nano)
			}

			if !endTime.IsZero() {
				endStr = endTime.Format(time.RFC3339Nano)
			}

			if startStr != "" {
				ipToTimes[ip] = append(ipToTimes[ip], startStr)
			}
			if endStr != "" && endStr != startStr {
				ipToTimes[ip] = append(ipToTimes[ip], endStr)
			}
		}

		// Only include this certificate if it has observations from other hosts
		if len(ipToTimes) > 0 {
			validHistObs[certKey] = ipToTimes
		}
	}

	// If no valid observations after filtering, don't print anything
	if len(validHistObs) == 0 {
		return
	}

	fmt.Fprintf(r.w, "\nHistorical Certificate Observations: %d\n", len(validHistObs))

	for certKey, ipToTimes := range validHistObs {
		tree := treeprint.New()
		tree.SetValue(certKey)

		// Sort IPs for consistent output
		ips := make([]string, 0, len(ipToTimes))
		for ip := range ipToTimes {
			ips = append(ips, ip)
		}
		sort.Strings(ips)

		// Add each IP with its median observation timestamp
		for _, ip := range ips {
			times := ipToTimes[ip]

			// Sort times to get median
			sort.Strings(times)

			// Get the median timestamp
			medianIdx := len(times) / 2
			medianTime := times[medianIdx]

			var display string
			if r.useLinks {
				link := fmt.Sprintf("https://platform.censys.io/hosts/%s?at_time=%s",
					url.QueryEscape(ip), url.QueryEscape(medianTime))
				display = fmt.Sprintf("%s: %s (%d observations)", medianTime, termlink.Link(ip, link), len(times))
			} else {
				display = fmt.Sprintf("%s: %s (%d observations)", medianTime, ip, len(times))
			}
			tree.AddNode(display)
		}

		fmt.Fprintln(r.w, tree.String())
	}
}

// PivotNode represents a node in the pivot tree structure
type PivotNode struct {
	IP       string       `json:"ip,omitempty"`
	Depth    int          `json:"depth,omitempty"`
	Via      string       `json:"via,omitempty"`
	AtTime   *time.Time   `json:"at_time,omitempty"`
	Labels   []string     `json:"labels,omitempty"`
	Threats  []string     `json:"threats,omitempty"`
	Children []*PivotNode `json:"children,omitempty"`
}

// CreatePivotTree generates a pivot tree from a slice of reports
func (r *Reporter) CreatePivotTree(reports []*Report) []*PivotNode {
	if len(reports) <= 1 {
		return nil
	}

	type Node struct {
		ip      string
		depth   int
		via     string
		parent  string
		atTime  *time.Time
		labels  []string
		threats []string
	}

	nodes := make(map[string]*Node)
	for _, rep := range reports {
		parent := ""
		depth := 0
		via := ""

		if ref := rep.GetReferrer(); ref != nil {
			parent = ref.GetHost()
			via = ref.GetVia().GetCenqlQuery()
			if parentNode, ok := nodes[parent]; ok {
				depth = parentNode.depth + 1
			}
		}

		nodes[rep.Host] = &Node{
			ip:      rep.Host,
			depth:   depth,
			via:     via,
			parent:  parent,
			atTime:  rep.AtTime,
			labels:  rep.Labels,
			threats: rep.Threats,
		}
	}

	childrenMap := make(map[string][]*Node)
	for _, node := range nodes {
		if node.parent != "" {
			childrenMap[node.parent] = append(childrenMap[node.parent], node)
		}
	}

	var roots []*Node
	for _, node := range nodes {
		if node.parent == "" {
			roots = append(roots, node)
		}
	}

	sort.Slice(roots, func(i, j int) bool { return roots[i].ip < roots[j].ip })

	var build func(parent string) []*PivotNode
	build = func(parent string) []*PivotNode {
		children := childrenMap[parent]
		if len(children) == 0 {
			return nil
		}

		var ipNodes []*PivotNode
		viaGroups := make(map[string][]*Node)

		for _, child := range children {
			if child.via == "" {
				ipNodes = append(ipNodes, &PivotNode{
					IP:       child.ip,
					Depth:    child.depth,
					AtTime:   child.atTime,
					Labels:   child.labels,
					Threats:  child.threats,
					Children: build(child.ip),
				})
			} else {
				viaGroups[child.via] = append(viaGroups[child.via], child)
			}
		}

		var viaNodes []*PivotNode
		var viaKeys []string
		for via := range viaGroups {
			viaKeys = append(viaKeys, via)
		}
		sort.Strings(viaKeys)

		for _, via := range viaKeys {
			group := viaGroups[via]
			var groupChildren []*PivotNode
			sort.Slice(group, func(i, j int) bool { return group[i].ip < group[j].ip })
			for _, child := range group {
				groupChildren = append(groupChildren, &PivotNode{
					IP:       child.ip,
					Depth:    child.depth,
					AtTime:   child.atTime,
					Labels:   child.labels,
					Threats:  child.threats,
					Children: build(child.ip),
				})
			}
			viaNodes = append(viaNodes, &PivotNode{
				Via:      via,
				Children: groupChildren,
			})
		}

		return append(ipNodes, viaNodes...)
	}

	var jsonRoots []*PivotNode
	for _, root := range roots {
		jsonRoots = append(jsonRoots, &PivotNode{
			IP:       root.ip,
			Depth:    root.depth,
			AtTime:   root.atTime,
			Labels:   root.labels,
			Threats:  root.threats,
			Children: build(root.ip),
		})
	}

	return jsonRoots
}

func (r *Reporter) printPivot(p iPivot) {
	query := p.cenqlQuery

	if r.useLinks {
		maxLen := r.termWidth - 30
		if len(query) > maxLen {
			query = query[:maxLen] + "..."
		}
		query = fmt.Sprintf("%s %s", termlink.Link("⮺", p.searchURL), query)
	}

	fmt.Fprintf(r.w, " - [%5d] %s\n", p.count, query)
}

// Pivots processes a slice of reports and prints interesting pivots
func (r *Reporter) Pivots(reps []*Report) {
	sort.Slice(reps, func(i, j int) bool {
		return reps[i].Host < reps[j].Host && reps[i].Depth < reps[j].Depth
	})

	seenpivot := make(map[string]iPivot)

	for _, rep := range reps {
		for _, p := range rep.Data {
			if p.IsInteresting {
				if _, ok := seenpivot[p.CenqlQuery]; ok {
					continue
				}

				seenpivot[p.CenqlQuery] = iPivot{
					searchURL:  p.SearchURL,
					cenqlQuery: p.CenqlQuery,
					count:      p.Count,
				}
			}
		}
	}

	if len(seenpivot) > 0 {
		var pivots []iPivot
		for _, p := range seenpivot {
			pivots = append(pivots, p)
		}

		sort.Slice(pivots, func(i, j int) bool {
			return pivots[i].count > pivots[j].count
		})

		fmt.Fprintln(r.w, "Interesting pivots:")
		for _, p := range pivots {
			r.printPivot(p)
		}
	}
}
