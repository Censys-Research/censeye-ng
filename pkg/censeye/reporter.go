package censeye

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

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
	if !r.useLinks {
		return ip
	}
	return termlink.Link(ip, fmt.Sprintf("https://platform.censys.io/hosts/%s", url.QueryEscape(ip)))
}

func (r *Reporter) linkQuery(q string) string {
	if !r.useLinks {
		return q
	}

	return fmt.Sprintf("%s %s",
		termlink.Link("→",
			fmt.Sprintf("https://platform.censys.io/search?q=%s", url.QueryEscape(q))), q)
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
		if r.useLinks && strings.Contains(linked, "→") {
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
		host := r.linkHost(root.IP)
		hostWithTags := r.formatHostWithTags(host, root.Labels, root.Threats)
		tree.SetValue(fmt.Sprintf("%s (depth %d)", hostWithTags, root.Depth))

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
			// This is an IP node
			host := r.linkHost(node.IP)
			hostWithTags := r.formatHostWithTags(host, node.Labels, node.Threats)
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

	// Check if this is a multi-IP analysis report
	isMultiIP := strings.HasPrefix(report.Host, "MultiIP-Analysis-")

	if isMultiIP {
		// Multi-IP report format with host_set column
		if r.useLinks {
			t.AppendHeader(table.Row{"→", "Host_Set", "Hosts", "Key", "Val"})
		} else {
			t.AppendHeader(table.Row{"Host_Set", "Hosts", "Key", "Val"})
		}
	} else {
		// Standard single-IP report format
		if r.useLinks {
			t.AppendHeader(table.Row{"→", "Hosts", "Key", "Val"})
		} else {
			t.AppendHeader(table.Row{"Hosts", "Key", "Val"})
		}
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

		if isMultiIP {
			// For multi-IP reports, use the HostSetCount from the entry
			hostSetCount := strconv.Itoa(entry.GetHostSetCount())
			cfmt, key, val := r.colorize(entry, key, val, strconv.FormatInt(count, 10))

			if r.useLinks {
				t.AppendRow(table.Row{
					termlink.Link("→", entry.GetSearchURL()),
					hostSetCount, // Host_Set column
					cfmt,         // Hosts column (total in Censys)
					key,
					text.WrapText(val, valColWidth),
				})
			} else {
				t.AppendRow(table.Row{
					hostSetCount, // Host_Set column
					cfmt,         // Hosts column (total in Censys)
					key,
					text.WrapText(val, valColWidth),
				})
			}
		} else {
			// Standard single-IP report format
			cfmt, key, val := r.colorize(entry, key, val, strconv.FormatInt(count, 10))

			if r.useLinks {
				t.AppendRow(table.Row{
					termlink.Link("→", entry.GetSearchURL()),
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
	}

	host := report.GetHost()
	viah := report.GetReferrer().GetHost()
	viaq := report.GetReferrer().GetVia().GetCenqlQuery()
	vial := report.GetReferrer().GetVia().GetSearchURL()
	via := viaq

	if r.useLinks {
		via = termlink.Link(viaq, vial)
		viah = termlink.Link(viah, fmt.Sprintf("https://platform.censys.io/hosts/%s", url.QueryEscape(viah)))
		if report.AtTime != nil {
			host = termlink.Link(host, fmt.Sprintf("https://platform.censys.io/hosts/%s?at_time=%s", url.QueryEscape(host), report.AtTime.Format("2006-01-02T15:04:05Z")))
		} else {
			host = termlink.Link(host, fmt.Sprintf("https://platform.censys.io/hosts/%s", url.QueryEscape(host)))
		}
	}

	var allVia string

	for _, viaEntry := range report.GetReferrer().GetAllVia() {
		allVia += viaEntry.GetCenqlQuery() + ", "
	}

	if isMultiIP {
		// Multi-IP analysis header
		fmt.Fprintf(r.w, "\n%s\n", report.Host)
		fmt.Fprintln(r.w, "Common Attributes Analysis:")
	} else {
		// Standard single-IP header
		hostWithTags := r.formatHostWithTags(host, report.Labels, report.Threats)
		fmt.Fprintf(r.w, "\n%s (depth: %d) (via: %s -- %s)\n", hostWithTags, report.GetDepth(), viah, via)

		if report.GetReferrer() != nil {
			fmt.Fprintf(r.w, "Parent IP: %s\n", r.linkHost(viah))
			fmt.Fprintln(r.w, "All matching queries:")
			for _, viaEntry := range report.GetReferrer().GetAllVia() {
				fmt.Fprintf(r.w, " - %s\n", r.formatViaQuery(viaEntry.GetCenqlQuery()))
			}
		}
	}

	t.Render()
}

// PivotNode represents a node in the pivot tree structure
type PivotNode struct {
	IP       string       `json:"ip,omitempty"`
	Depth    int          `json:"depth,omitempty"`
	Via      string       `json:"via,omitempty"`
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
		// Don't truncate by default - users want to see full queries
		query = fmt.Sprintf("%s %s", termlink.Link("→", p.searchURL), query)
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

		fmt.Fprintln(r.w, "\nInteresting pivots:")
		for _, p := range pivots {
			r.printPivot(p)
		}
	}
}
