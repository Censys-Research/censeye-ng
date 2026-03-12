package aianalyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

const DefaultModel = "gpt-4o-mini"

func (c *Client) ChatCompletion(ctx context.Context, model string, systemPrompt, userPrompt string) (content string, err error) {
	if model == "" {
		model = DefaultModel
	}
	endpoint := strings.TrimRight(c.cfg.Endpoint, "/") + "/v1/chat/completions"

	msgs := []map[string]string{}
	if systemPrompt != "" {
		msgs = append(msgs, map[string]string{"role": "system", "content": systemPrompt})
	}
	msgs = append(msgs, map[string]string{"role": "user", "content": userPrompt})

	reqBody := map[string]any{
		"model":       model,
		"temperature": 0,
		"messages":    msgs,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("llm returned %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("parse llm response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("no choices in llm response")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

// MaxBodyBytesForLLM is the maximum HTTP body length (in bytes) sent to the LLM to avoid token limits.
const MaxBodyBytesForLLM = 20 * 1024

func (c *Client) RunExtractRegexFromBody(ctx context.Context, body string) ([]string, error) {
	if len(body) > MaxBodyBytesForLLM {
		body = body[:MaxBodyBytesForLLM]
	}

	userPrompt := fmt.Sprintf(StubUserPrompt, body)
	content, err := c.ChatCompletion(ctx, DefaultModel, StubSystemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	content = strings.TrimSpace(content)
	log.Printf("LLM response content: %s", content)
	var result []string
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("parse llm regex array: %w", err)
	}

	return result, nil
}
