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

func TestPivotTreeHoistsSharedAlsoVia(t *testing.T) {
	primary := entry("host.services.cert.fingerprint_sha256", "0750f2")
	subjectDN := entry("host.services.cert.parsed.subject_dn", "CN=chessroyale.app")
	commonName := entry("host.services.cert.parsed.subject.common_name", "chessroyale.app")
	bodyHash := entry("host.services.endpoints.http.body_hash_sha256", "4a66f6")

	reports := []*Report{
		{Host: "1.1.1.1", Depth: 0},
		// three hosts share {subjectDN, commonName}; one also has bodyHash.
		{Host: "3.124.61.92", Depth: 1, Referrer: &Referrer{Host: "1.1.1.1", Via: []*reportEntry{primary, subjectDN, commonName}}},
		{Host: "3.125.201.74", Depth: 1, Referrer: &Referrer{Host: "1.1.1.1", Via: []*reportEntry{primary, subjectDN, commonName}}},
		{Host: "35.159.75.206", Depth: 1, Referrer: &Referrer{Host: "1.1.1.1", Via: []*reportEntry{primary, subjectDN, commonName, bodyHash}}},
	}

	var buf bytes.Buffer
	r := NewReporter(&buf, "no-colors", "no-links")
	r.PivotTree(reports)

	out := buf.String()
	t.Logf("\n%s", out)

	// the shared queries should be hoisted once under the group node.
	if !strings.Contains(out, "also via (all 3 hosts):") {
		t.Fatalf("expected hoisted shared-via section, got:\n%s", out)
	}
	if strings.Count(out, "common_name=\"chessroyale.app\"") != 1 {
		t.Fatalf("expected shared common_name query listed exactly once, got:\n%s", out)
	}
	if strings.Count(out, "subject_dn=\"CN=chessroyale.app\"") != 1 {
		t.Fatalf("expected shared subject_dn query listed exactly once, got:\n%s", out)
	}
	// the body_hash query is unique to one host and must remain under it.
	if strings.Count(out, "body_hash_sha256=\"4a66f6\"") != 1 {
		t.Fatalf("expected unique body_hash query listed once under its host, got:\n%s", out)
	}
}
