package aianalyzer

import (
	"net/url"
	"os"
)

const (
	DefaultAPIKeyEnv   = "LITE_LLM_API_KEY"
	DefaultEndpointEnv = "LITE_LLM_ENDPOINT"
)

// Config holds LiteLLM API configuration (API key and endpoint URL).
type Config struct {
	APIKey   string
	Endpoint string
}

type Client struct{ cfg Config }

func ConfigFromEnv() Config {
	return Config{
		APIKey:   os.Getenv(DefaultAPIKeyEnv),
		Endpoint: os.Getenv(DefaultEndpointEnv),
	}
}

func (c Config) Valid() bool {
	if c.APIKey == "" || c.Endpoint == "" {
		return false
	}

	u, err := url.Parse(c.Endpoint)

	return err == nil && u.Scheme != "" && u.Host != ""
}

func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

func NewFromEnv() *Client {
	return New(ConfigFromEnv())
}

func (c *Client) Cfg() Config {
	return c.cfg
}
