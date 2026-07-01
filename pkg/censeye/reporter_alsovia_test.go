package censeye

import (
	"bytes"
	"strings"
	"testing"

	"github.com/censys/censys-sdk-go/models/components"
)

func entry(field, value string) *reportEntry {
	e := &reportEntry{
		Pairs: []components.FieldValuePair{{Field: field, Value: value}},
	}
	e.CenqlQuery = e.ToCenqlQuery()
	return e
}

func TestPivotTreeShowsAlsoVia(t *testing.T) {
	certVia := entry("host.services.cert.parsed.subject_dn", "O=Organization")
	ja4Via := entry("host.services.ja4tscan.fingerprint", "65160_2-4-8-1-3_1424_7_1-2-4-8-16")
	bodyVia := entry("host.services.http.body_hash", "sha256:deadbeef")

	reports := []*Report{
		{Host: "113.45.185.225", Depth: 0},
		// child matched by three of the parent's queries; first is primary.
		{
			Host:     "115.159.25.200",
			Depth:    1,
			Referrer: &Referrer{Host: "113.45.185.225", Via: []*reportEntry{certVia, ja4Via, bodyVia}},
		},
		// sibling matched by only the primary query.
		{
			Host:     "101.34.83.47",
			Depth:    1,
			Referrer: &Referrer{Host: "113.45.185.225", Via: []*reportEntry{certVia}},
		},
	}

	var buf bytes.Buffer
	r := NewReporter(&buf, "no-colors", "no-links")
	r.PivotTree(reports)

	out := buf.String()
	t.Logf("\n%s", out)

	if !strings.Contains(out, "also via:") {
		t.Fatalf("expected 'also via:' section in output, got:\n%s", out)
	}
	if !strings.Contains(out, "ja4tscan.fingerprint") {
		t.Fatalf("expected second matching query (ja4tscan) in output, got:\n%s", out)
	}
	if !strings.Contains(out, "body_hash") {
		t.Fatalf("expected third matching query (body_hash) in output, got:\n%s", out)
	}
}
