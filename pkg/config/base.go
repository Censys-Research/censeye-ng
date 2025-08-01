package config

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Workdir          string            `yaml:"workdir,omitempty"`
	ExtractionRules  []*ExtractionRule `yaml:"extraction_rules,omitempty"`
	Filters          []string          `yaml:"filters,omitempty"`
	RgxFilters       []*regexp.Regexp  `yaml:"re_filters,omitempty"`
	KeyValuePrefixes []string          `yaml:"key_value_prefixes,omitempty"`
	PivotableFields  []string          `yaml:"pivotable_fields,omitempty"`
	Rarity           *Rarity           `yaml:"rarity,omitempty"`
	CacheDuration    time.Duration     `yaml:"cache_duration,omitempty"`
	Workers          int               `yaml:"workers,omitempty"`
}

type ExtractionRule struct {
	Scope  string   `yaml:"scope,omitempty"`
	Fields []string `yaml:"fields,omitempty"`
}

type Rarity struct {
	Min uint64 `yaml:"min,omitempty"`
	Max uint64 `yaml:"max,omitempty"`
}

func (c *Config) GetExtractionRules() []*ExtractionRule {
	if c == nil || c.ExtractionRules == nil {
		return DefaultExtractionRules
	}

	return c.ExtractionRules
}

func (c *Config) GetFilters() []string {
	if c == nil || c.Filters == nil {
		return DefaultFilters
	}

	return c.Filters
}

func (c *Config) GetRegexFilters() []*regexp.Regexp {
	if c == nil || c.RgxFilters == nil {
		return DefaultRgxFilters
	}

	return c.RgxFilters
}

func (c *Config) GetKeyValuePrefixes() []string {
	if c == nil || c.KeyValuePrefixes == nil {
		return DefaultKeyValuePrefixes
	}

	return c.KeyValuePrefixes
}

func (c *Config) GetPivotableFields() []string {
	if c == nil || c.PivotableFields == nil {
		return DefaultPivotableFields
	}

	return c.PivotableFields
}

func (r *Rarity) IsInteresting(value uint64) bool {
	if r == nil {
		return false
	}
	return value >= r.Min && value <= r.Max
}

func (e *ExtractionRule) GetScope() string {
	if e == nil {
		return ""
	}
	return e.Scope
}

func (e *ExtractionRule) GetFields() []string {
	if e == nil {
		return nil
	}
	return e.Fields
}

type ConfigOption func(*Config)

func WithRegexFilters(filters []*regexp.Regexp) ConfigOption {
	return func(c *Config) {
		c.RgxFilters = filters
	}
}

func WithExtractionRules(rules []*ExtractionRule) ConfigOption {
	return func(c *Config) {
		c.ExtractionRules = rules
	}
}

func WithFilters(filters []string) ConfigOption {
	return func(c *Config) {
		c.Filters = filters
	}
}

func WithRarity(rarity *Rarity) ConfigOption {
	return func(c *Config) {
		c.Rarity = rarity
	}
}

func WithCacheDuration(duration time.Duration) ConfigOption {
	return func(c *Config) {
		c.CacheDuration = duration
	}
}

func WithWorkers(workers int) ConfigOption {
	return func(c *Config) {
		c.Workers = workers
	}
}

func WithWorkdir(workdir string) ConfigOption {
	return func(c *Config) {
		c.Workdir = workdir
	}
}

func WithPivotableFields(fields []string) ConfigOption {
	return func(c *Config) {
		c.PivotableFields = fields
	}
}

func NewConfig(options ...ConfigOption) *Config {
	config := &Config{
		ExtractionRules: DefaultExtractionRules,
		Filters:         DefaultFilters,
		Rarity:          DefaultRarity,
		CacheDuration:   DefaultCacheDuration,
		Workers:         DefaultWorkers,
		RgxFilters:      DefaultRgxFilters,
		PivotableFields: DefaultPivotableFields,
	}

	for _, option := range options {
		option(config)
	}

	// always keep this default, it's a statically defined constant
	config.KeyValuePrefixes = DefaultKeyValuePrefixes

	return config
}

func Parse(r io.Reader) (*Config, error) {
	decoder := yaml.NewDecoder(r)
	config := &Config{}

	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return config, nil
}

func ParseFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	return Parse(file)
}
