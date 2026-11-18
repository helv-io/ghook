package pubsubx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPullAckAndCreate(t *testing.T) {
	note := base64.StdEncoding.EncodeToString([]byte(`{"emailAddress":"ada@example.com","historyId":9}`))
	var acked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch {
		case strings.HasSuffix(r.URL.Path, ":pull"):
			_, _ = w.Write([]byte(`{"receivedMessages":[{"ackId":"a1","message":{"data":"` + note + `"}}]}`))
		case strings.HasSuffix(r.URL.Path, ":acknowledge"):
			var body struct {
				AckIDs []string `json:"ackIds"`
			}
			_ = json.Unmarshal(b, &body)
			acked = body.AckIDs
			w.WriteHeader(200)
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"etag":"e","bindings":[]}`))
		case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
			if !strings.Contains(string(b), "gmail-api-push@system.gserviceaccount.com") {
				t.Errorf("publisher missing: %s", b)
			}
			w.WriteHeader(200)
		case r.Method == http.MethodGet:
			http.NotFound(w, r)
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	api := &API{Base: srv.URL, HTTP: srv.Client(), Token: func(context.Context) (string, error) { return "tok", nil }}
	sub := SubPath("demo", "ghook")
	msgs, err := api.Pull(context.Background(), sub, 5)
	if err != nil || len(msgs) != 1 || string(msgs[0].Data) == "" || msgs[0].AckID != "a1" {
		t.Fatal(err, msgs)
	}
	if err := api.Ack(context.Background(), sub, []string{msgs[0].AckID}); err != nil {
		t.Fatal(err)
	}
	if len(acked) != 1 || acked[0] != "a1" {
		t.Fatal(acked)
	}
	topic := TopicPath("demo", "ghook")
	if err := api.CreateTopic(context.Background(), topic); err != nil {
		t.Fatal(err)
	}
	if err := api.CreateSubscription(context.Background(), sub, topic); err != nil {
		t.Fatal(err)
	}
	if err := api.GrantGmailPublish(context.Background(), topic); err != nil {
		t.Fatal(err)
	}
}
