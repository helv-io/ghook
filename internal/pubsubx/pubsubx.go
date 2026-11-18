// Package pubsubx talks to Cloud Pub/Sub over HTTPS. Pull mode needs no public
// URL. Push mode verifies the OIDC JWT Google attaches to the request.
package pubsubx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const gmailPublisher = "serviceAccount:gmail-api-push@system.gserviceaccount.com"

// Message is one pulled Pub/Sub message. Data is the raw Gmail notification.
type Message struct {
	AckID string
	Data  []byte
}

// Token returns a bearer token for the Pub/Sub API.
type Token func(ctx context.Context) (string, error)

// API is a small REST client.
type API struct {
	HTTP  *http.Client
	Token Token
	Base  string // default https://pubsub.googleapis.com/v1
}

func (a *API) http() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (a *API) base() string {
	if a.Base != "" {
		return strings.TrimRight(a.Base, "/")
	}
	return "https://pubsub.googleapis.com/v1"
}

func (a *API) do(ctx context.Context, method, url string, body any) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.Token != nil {
		tok, err := a.Token(ctx)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := a.http().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	slurp, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return slurp, res.StatusCode, fmt.Errorf("pubsub %s: %s", res.Status, clip(string(slurp)))
	}
	return slurp, res.StatusCode, nil
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

// TopicPath accepts a short name or a full resource name.
func TopicPath(project, topic string) string {
	topic = strings.TrimSpace(topic)
	if strings.HasPrefix(topic, "projects/") {
		return topic
	}
	return "projects/" + strings.TrimSpace(project) + "/topics/" + topic
}

// SubPath accepts a short name or a full resource name.
func SubPath(project, sub string) string {
	sub = strings.TrimSpace(sub)
	if strings.HasPrefix(sub, "projects/") {
		return sub
	}
	return "projects/" + strings.TrimSpace(project) + "/subscriptions/" + sub
}

// Pull fetches up to max messages.
func (a *API) Pull(ctx context.Context, sub string, max int) ([]Message, error) {
	if max <= 0 {
		max = 10
	}
	raw, _, err := a.do(ctx, http.MethodPost, a.base()+"/"+sub+":pull", map[string]any{"maxMessages": max})
	if err != nil {
		return nil, err
	}
	var resp struct {
		ReceivedMessages []struct {
			AckID   string `json:"ackId"`
			Message struct {
				Data string `json:"data"`
			} `json:"message"`
		} `json:"receivedMessages"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	var out []Message
	for _, m := range resp.ReceivedMessages {
		data, err := base64.StdEncoding.DecodeString(m.Message.Data)
		if err != nil {
			data, _ = base64.RawStdEncoding.DecodeString(m.Message.Data)
		}
		out = append(out, Message{AckID: m.AckID, Data: data})
	}
	return out, nil
}

// Ack acknowledges messages that were durably queued.
func (a *API) Ack(ctx context.Context, sub string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, _, err := a.do(ctx, http.MethodPost, a.base()+"/"+sub+":acknowledge", map[string]any{"ackIds": ids})
	return err
}

// Exists reports whether the resource is there. A 404 is false, nil.
func (a *API) Exists(ctx context.Context, resource string) (bool, error) {
	_, code, err := a.do(ctx, http.MethodGet, a.base()+"/"+resource, nil)
	if err == nil {
		return true, nil
	}
	if code == http.StatusNotFound {
		return false, nil
	}
	return false, err
}

// CreateTopic creates the topic if it does not exist.
func (a *API) CreateTopic(ctx context.Context, topic string) error {
	ok, err := a.Exists(ctx, topic)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	_, _, err = a.do(ctx, http.MethodPut, a.base()+"/"+topic, map[string]any{})
	return err
}

// CreateSubscription creates a pull subscription with a 7 day retention and a
// 60 second ack deadline. An empty expiration ttl means it does not expire.
func (a *API) CreateSubscription(ctx context.Context, sub, topic string) error {
	ok, err := a.Exists(ctx, sub)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	body := map[string]any{
		"topic": topic, "ackDeadlineSeconds": 60,
		"messageRetentionDuration": "604800s",
		"expirationPolicy":         map[string]string{"ttl": ""},
	}
	_, _, err = a.do(ctx, http.MethodPut, a.base()+"/"+sub, body)
	return err
}

// GrantGmailPublish gives gmail-api-push publisher on the topic.
func (a *API) GrantGmailPublish(ctx context.Context, topic string) error {
	raw, _, err := a.do(ctx, http.MethodGet, a.base()+"/"+topic+":getIamPolicy", nil)
	if err != nil {
		return err
	}
	var policy struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
		Etag string `json:"etag"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return err
	}
	found := false
	for i := range policy.Bindings {
		if policy.Bindings[i].Role != "roles/pubsub.publisher" {
			continue
		}
		for _, m := range policy.Bindings[i].Members {
			if m == gmailPublisher {
				return nil
			}
		}
		policy.Bindings[i].Members = append(policy.Bindings[i].Members, gmailPublisher)
		found = true
	}
	type binding struct {
		Role    string   `json:"role"`
		Members []string `json:"members"`
	}
	var bindings []binding
	for _, b := range policy.Bindings {
		bindings = append(bindings, binding{Role: b.Role, Members: b.Members})
	}
	if !found {
		bindings = append(bindings, binding{Role: "roles/pubsub.publisher", Members: []string{gmailPublisher}})
	}
	_, _, err = a.do(ctx, http.MethodPost, a.base()+"/"+topic+":setIamPolicy", map[string]any{
		"policy": map[string]any{"bindings": bindings, "etag": policy.Etag},
	})
	return err
}

// ErrNotConfigured is returned when Pub/Sub has no credentials.
var ErrNotConfigured = errors.New("pubsub credentials are not configured")
