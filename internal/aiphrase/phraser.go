// Package aiphrase is the optional language-model adapter for the assistant.
//
// Boundary: the model receives the question and the already computed,
// permission-filtered answer (text and facts) and may only rephrase it. It
// has no tools, no database access and no secrets; it cannot act. The
// kernel discards any phrasing that mentions a number not present in the
// facts. The adapter speaks the OpenAI-compatible chat-completions API so a
// hosted or a self-hosted model can be used. It is off unless configured.
package aiphrase

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config selects the model endpoint.
type Config struct {
	Endpoint string // e.g. https://api.openai.com/v1/chat/completions
	APIKey   string
	Model    string
	Timeout  time.Duration
}

// Client is a Phraser.
type Client struct {
	cfg  Config
	http *http.Client
}

// New validates the configuration (https only, unless localhost).
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
		return nil, errors.New("aiphrase: endpoint must be an https URL (http only for localhost)")
	}
	if cfg.Model == "" {
		return nil, errors.New("aiphrase: model is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 8 * time.Second
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}}, nil
}

const system = "You rewrite a construction-management answer for a busy manager. You are given the question, the exact answer text and the facts behind it. " +
	"Rewrite the answer in clear plain English in at most 120 words. Keep every number, name and reference exactly as given. Do not add numbers, " +
	"estimates, causes or advice that are not in the facts. If the facts say something is missing or cannot be assessed, say so. Never claim certainty the facts do not give."

// Phrase asks the model for a rephrasing. Any failure returns an error and
// the caller keeps the deterministic text.
func (c *Client) Phrase(ctx context.Context, question string, facts any) (string, error) {
	fb, err := json.Marshal(facts)
	if err != nil {
		return "", err
	}
	if len(fb) > 24_000 {
		fb = fb[:24_000]
	}
	body, _ := json.Marshal(map[string]any{"model": c.cfg.Model, "temperature": 0.2, "max_tokens": 300,
		"messages": []map[string]string{{"role": "system", "content": system},
			{"role": "user", "content": "Question: " + question + "\n\nAnswer and facts (JSON):\n" + string(fb)}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("aiphrase: model endpoint answered %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(rb, &out); err != nil || len(out.Choices) == 0 {
		return "", errors.New("aiphrase: unexpected response")
	}
	text := strings.TrimSpace(out.Choices[0].Message.Content)
	if text == "" || len(text) > 2000 {
		return "", errors.New("aiphrase: empty or oversized phrasing")
	}
	return text, nil
}
