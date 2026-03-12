package censeye

import (
	"github.com/tidwall/gjson"
)

// HTTPBodyWithHash holds an HTTP response body and its SHA-256 hash from the host data.
type HTTPBodyWithHash struct {
	Hash string // body_hash_sha256 from services[].endpoints[].http.body_hash_sha256
	Body string // from services[].endpoints[].http.body
}

// extractHTTPBodiesWithHash iterates host JSON (res) and collects HTTP bodies with length >= minBodyBytes
// and their body_hash_sha256. Only entries with both body and hash are included. Results are deduped by Hash.
func extractHTTPBodiesWithHash(res gjson.Result, minBodyBytes int) []HTTPBodyWithHash {
	services := res.Get("services")
	if !services.Exists() || !services.IsArray() {
		return nil
	}

	seen := make(map[string]struct{})
	var out []HTTPBodyWithHash

	for _, service := range services.Array() {
		endpoints := service.Get("endpoints")
		if !endpoints.Exists() || !endpoints.IsArray() {
			continue
		}
		for _, ep := range endpoints.Array() {
			httpPart := ep.Get("http")
			if !httpPart.Exists() {
				continue
			}
			body := httpPart.Get("body")
			hash := httpPart.Get("body_hash_sha256")
			if !body.Exists() || body.Type != gjson.String ||
				!hash.Exists() || hash.Type != gjson.String {
				continue
			}
			b := body.String()
			h := hash.String()
			if len(b) < minBodyBytes || h == "" {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, HTTPBodyWithHash{Hash: h, Body: b})
		}
	}

	return out
}
