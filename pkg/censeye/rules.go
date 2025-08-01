package censeye

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/censys/censys-sdk-go/models/components"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// isKeyValueObject checks if the given prefix should be treated as a key-value object
// or if it has the traditional "headers" structure
func (c *Censeye) isKeyValueObject(v gjson.Result, pfx string) bool {
	// Check if this prefix is in the configured key-value prefixes list
	if slices.Contains(c.config.GetKeyValuePrefixes(), pfx) {
		return true
	}

	// Original logic for detecting header structures
	if !v.IsObject() {
		return false
	}

	result := true
	v.ForEach(func(_, val gjson.Result) bool {
		if !val.IsObject() || !val.Get("headers").Exists() {
			result = false
			return false
		}
		return true
	})

	return result
}

// genCombos creates all combinations of field values for a rule, used specifically for service extraction rules.
// This is a special case for odd ways censys formats some data, for example in this host.cert.parsed entry:
//
//	"subject": {
//		"common_name": [ "localhost" ],
//		"locality": [ "The Sewers" ],
//		"organization": [ "Pant, Inc." ],
//		"province": [ "Hamai" ]
//	}
//
// we DON'T want to generate `host.cert.parsed.subject.common_name=["localhost"]` but instead generate `host.cert.parsed.common_name="localhost"`
func genCombos(fieldValues map[string][]string, fields []string, pfx string) [][]components.FieldValuePair {
	if len(fields) == 0 {
		return [][]components.FieldValuePair{}
	}

	// build the list of field names along with the prefix
	fieldNames := make([]string, len(fields))
	for i, field := range fields {
		fieldNames[i] = pfx + "." + field
	}

	var combinations [][]components.FieldValuePair
	genCartesian(fieldValues, fieldNames, 0, []components.FieldValuePair{}, &combinations)
	log.Debugf("Generated %d combinations for fields %v", len(combinations), fieldNames)

	return combinations
}

// genCartesian recursively generates all combinations of field values.
func genCartesian(fieldValues map[string][]string, fieldNames []string, index int, current []components.FieldValuePair, result *[][]components.FieldValuePair) {
	if index == len(fieldNames) {
		// just amke a copy of our current data and add it to the result...
		combination := make([]components.FieldValuePair, len(current))
		copy(combination, current)
		*result = append(*result, combination)
		return
	}

	fieldName := fieldNames[index]
	values := fieldValues[fieldName]

	for _, value := range values {
		current = append(current, components.FieldValuePair{
			Field: fieldName,
			Value: value,
		})
		genCartesian(fieldValues, fieldNames, index+1, current, result)
		current = current[:len(current)-1] // backtrack
	}
}

func (c *Censeye) compileFieldRules(in gjson.Result, pfx string, ret *[][]components.FieldValuePair) error {
	if in.IsObject() {
		if c.isKeyValueObject(in, pfx) {
			log.Debugf("compiling key-value rules for object at prefix %s", pfx)

			// Check if this is a configured key-value prefix (direct key-value pairs)
			isConfiguredPrefix := slices.Contains(c.config.GetKeyValuePrefixes(), pfx)

			if isConfiguredPrefix {
				// Handle direct key-value pairs for configured prefixes
				in.ForEach(func(k, v gjson.Result) bool {
					*ret = append(*ret, []components.FieldValuePair{
						{Field: pfx + ".key", Value: k.String()},
						{Field: pfx + ".value", Value: v.String()},
					})
					return true
				})
			} else {
				// Handle original "headers" structure
				in.ForEach(func(k, v gjson.Result) bool {
					hdrs := v.Get("headers")
					if hdrs.Exists() && hdrs.IsArray() && len(hdrs.Array()) > 0 {
						*ret = append(*ret, []components.FieldValuePair{
							{Field: pfx + ".key", Value: k.String()},
							{Field: pfx + ".value", Value: hdrs.Array()[0].String()},
						})
					}
					return true
				})
			}

			return nil
		}
		in.ForEach(func(k, v gjson.Result) bool {
			if err := c.compileFieldRules(v, pfx+"."+k.String(), ret); err != nil {
				return false
			}
			return true
		})
	} else if in.IsArray() {
		for _, subv := range in.Array() {
			if err := c.compileFieldRules(subv, pfx, ret); err != nil {
				return fmt.Errorf("error compiling field rules for array: %w", err)
			}
		}
	} else if in.Type == gjson.String {
		*ret = append(*ret, []components.FieldValuePair{{Field: pfx, Value: in.String()}})
	} else if in.Type == gjson.Number {
		*ret = append(*ret, []components.FieldValuePair{{Field: pfx, Value: in.Raw}})
	} else if in.Type == gjson.True || in.Type == gjson.False {
		// skip booleans as they are not statistically interesting....
	} else {
		*ret = append(*ret, []components.FieldValuePair{{Field: pfx, Value: in.String()}})
	}

	return nil
}

func (c *Censeye) compileServiceRules(in gjson.Result, _ string, ret *[][]components.FieldValuePair) error {
	services := in.Get("services")
	if !services.Exists() || !services.IsArray() {
		log.Warn("no services found in input, skipping special collection")
		return nil
	}

	for _, service := range services.Array() {
		for _, rule := range c.config.GetExtractionRules() {
			var entries []gjson.Result

			if rule.Scope == "" {
				entries = []gjson.Result{service}
			} else {
				scopeVal := service.Get(rule.Scope)
				if !scopeVal.Exists() || !scopeVal.IsArray() {
					continue
				}
				entries = scopeVal.Array()
			}

			for _, entry := range entries {
				// first, we collect all field values and check if all fields exist to satisfy this specific extraction rule
				fieldValues := make(map[string][]string)
				allExist := true

				pfx := "host.services"
				if rule.Scope != "" {
					pfx += "." + rule.Scope
				}

				for _, field := range rule.GetFields() {
					val := entry.Get(field)
					if !val.Exists() {
						allExist = false
						break
					}

					var values []string
					if val.IsArray() {
						for _, arrVal := range val.Array() {
							values = append(values, arrVal.String())
						}
					} else {
						values = append(values, val.String())
					}

					fieldValues[pfx+"."+field] = values
				}

				if !allExist {
					continue
				}

				// now we generate all combos of field values
				combos := genCombos(fieldValues, rule.GetFields(), pfx)
				*ret = append(*ret, combos...)
			}
		}
	}
	return nil
}

// optimizeRules filters and de-duplicates the rules based on the configuration filters.
func (c *Censeye) optimizeRules(rules [][]components.FieldValuePair) [][]components.FieldValuePair {
	filtered := make([][]components.FieldValuePair, 0)

	// first filter out all the rules that match our configuration filter.
	for _, rule := range rules {
		shouldSkip := false

		for _, fv := range rule {
			for _, prefix := range c.config.GetFilters() {
				if strings.HasSuffix(prefix, ".") {
					if strings.HasPrefix(fv.GetField(), prefix) {
						shouldSkip = true
						break
					}
				} else {
					if fv.GetField() == prefix {
						shouldSkip = true
						break
					}
				}
			}
			if shouldSkip {
				break
			}
		}

		if shouldSkip {
			continue
		}

		filtered = append(filtered, rule)
	}

	// now we de-duplicate the filtered rules.
	ret := make([][]components.FieldValuePair, 0)
	seen := make(map[string]bool)

	serialize := func(fvs []components.FieldValuePair) string {
		out := make([]string, len(fvs))
		for i, fv := range fvs {
			out[i] = fv.GetField() + "=" + fv.GetValue()
		}
		sort.Strings(out)
		return strings.Join(out, "|")
	}

	for _, rule := range filtered {
		serialized := serialize(rule)
		if _, exists := seen[serialized]; !exists {
			seen[serialized] = true
			ret = append(ret, rule)
		}
	}

	return ret
}

func (c *Censeye) applyRegexFilters(pairs [][]components.FieldValuePair) [][]components.FieldValuePair {
	ret := make([][]components.FieldValuePair, 0)
	regexes := c.config.GetRegexFilters()

	for _, pair := range pairs {
		ent := &reportEntry{Pairs: pair}
		cql := ent.ToCenqlQuery()

		skip := false
		for _, rgx := range regexes {
			if rgx.MatchString(cql) {
				log.Debugf("Skipping rule %s due to regex filter %s", cql, rgx.String())
				skip = true
				break
			}
		}

		if !skip {
			ret = append(ret, pair)
		}
	}

	return ret
}

func (c *Censeye) compileRules(input gjson.Result) ([][]components.FieldValuePair, error) {
	ret := make([][]components.FieldValuePair, 0)

	if err := c.compileFieldRules(input, defaultPfx, &ret); err != nil {
		return nil, fmt.Errorf("error compiling field rules: %w", err)
	}

	if err := c.compileServiceRules(input, defaultPfx, &ret); err != nil {
		return nil, fmt.Errorf("error compiling service rules: %w", err)
	}

	ret = c.optimizeRules(ret)
	ret = c.applyRegexFilters(ret)

	return ret, nil
}

func (c *Censeye) CompileRulesFromHostResult(input []byte) (*components.SearchValueCountsInputBody, error) {
	res := gjson.ParseBytes(input)
	if !res.IsObject() {
		return nil, fmt.Errorf("input is not a valid JSON object")
	}

	// Check if JSON has result.resource structure and extract it if present
	if resultResource := res.Get("result.resource"); resultResource.Exists() && resultResource.IsObject() {
		res = resultResource
	}

	rules, err := c.compileRules(res)
	if err != nil {
		return nil, fmt.Errorf("error compiling rules: %w", err)
	}

	if len(rules) == 0 {
		log.Warn("no rules compiled from input")
	}

	rules = c.optimizeRules(rules)
	ret := components.SearchValueCountsInputBody{
		AndCountConditions: make([]components.CountCondition, 0),
	}

	for _, rule := range rules {
		srule := components.CountCondition{
			FieldValuePairs: rule,
		}
		ret.AndCountConditions = append(ret.AndCountConditions, srule)
	}

	return &ret, nil
}

func CompileRulesFromHostResult(input []byte) (*components.SearchValueCountsInputBody, error) {
	c := &Censeye{}
	return c.CompileRulesFromHostResult(input)
}

func ValueCountsInputBodyToCenql(input *components.SearchValueCountsInputBody) ([]string, error) {
	// func (c *Censeye) makeEntry(pairs []components.FieldValuePair, count uint64) *reportEntry {
	entries := make([]string, 0, len(input.AndCountConditions))
	for _, condition := range input.AndCountConditions {
		ent := &reportEntry{Pairs: condition.FieldValuePairs}
		cql := ent.ToCenqlQuery()
		if cql == "" {
			continue
		}
		entries = append(entries, cql)
	}
	return entries, nil
}
