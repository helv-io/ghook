package gmailx

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/helv-io/ghook/internal/mail"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// Scopes.
const (
	ScopeReadonly = "https://www.googleapis.com/auth/gmail.readonly"
	ScopeModify   = "https://www.googleapis.com/auth/gmail.modify"
	ScopeSettings = "https://www.googleapis.com/auth/gmail.settings.basic"
	ScopePubSub   = "https://www.googleapis.com/auth/pubsub"
)

// ScopeList builds the least-privilege set. Modify replaces readonly.
// Settings and Pub/Sub are opt-in.
func ScopeList(modify, settings, pubsub bool) []string {
	var s []string
	if modify {
		s = append(s, ScopeModify)
	} else {
		s = append(s, ScopeReadonly)
	}
	if settings {
		s = append(s, ScopeSettings)
	}
	if pubsub {
		s = append(s, ScopePubSub)
	}
	return s
}

// TokenSave persists a refreshed access token.
type TokenSave func(refresh, access string, expiry time.Time)

// Dial builds a client for one mailbox. clientJSON is the OAuth client file
// from Google. The refresh token is required.
func Dial(ctx context.Context, clientJSON, refresh, access string, expiry time.Time, scopes []string, save TokenSave) (*Live, error) {
	if strings.TrimSpace(clientJSON) == "" {
		return nil, errors.New("upload the Google OAuth client first")
	}
	if refresh == "" {
		return nil, errors.New("mailbox has no refresh token")
	}
	cfg, err := google.ConfigFromJSON([]byte(clientJSON), scopes...)
	if err != nil {
		return nil, fmt.Errorf("oauth client file: %w", err)
	}
	tok := &oauth2.Token{RefreshToken: refresh, AccessToken: access, Expiry: expiry}
	// last starts at the cached token, so only a real refresh is written back.
	// Saving on every Dial rewrote the account row on every Gmail call.
	src := &savingSource{base: oauth2.ReuseTokenSource(tok, cfg.TokenSource(ctx, tok)), refresh: refresh, last: access, save: save}
	svc, err := gmail.NewService(ctx, option.WithTokenSource(src))
	if err != nil {
		return nil, err
	}
	return &Live{svc: svc}, nil
}

type savingSource struct {
	base    oauth2.TokenSource
	refresh string
	last    string
	save    TokenSave
}

func (s *savingSource) Token() (*oauth2.Token, error) {
	t, err := s.base.Token()
	if err != nil {
		return nil, err
	}
	if s.save != nil && t.AccessToken != "" && t.AccessToken != s.last {
		s.last = t.AccessToken
		ref := t.RefreshToken
		if ref == "" {
			ref = s.refresh
		}
		s.save(ref, t.AccessToken, t.Expiry)
	}
	return t, nil
}

// Config returns an oauth2 config for the connect button.
func Config(clientJSON, redirect string, scopes []string) (*oauth2.Config, error) {
	cfg, err := google.ConfigFromJSON([]byte(clientJSON), scopes...)
	if err != nil {
		return nil, err
	}
	cfg.RedirectURL = redirect
	return cfg, nil
}

// ClientID reads the client id out of a downloaded client file. The secret is not returned.
func ClientID(clientJSON string) (string, error) {
	cfg, err := google.ConfigFromJSON([]byte(clientJSON), ScopeReadonly)
	if err != nil {
		return "", err
	}
	return cfg.ClientID, nil
}

// Live is the Gmail API.
type Live struct {
	svc *gmail.Service
}

func (l *Live) Profile(ctx context.Context) (string, string, error) {
	p, err := l.svc.Users.GetProfile("me").Context(ctx).Do()
	if err != nil {
		return "", "", err
	}
	return p.EmailAddress, strconv.FormatUint(p.HistoryId, 10), nil
}

func (l *Live) Watch(ctx context.Context, topic string) (string, time.Time, error) {
	w, err := l.svc.Users.Watch("me", &gmail.WatchRequest{TopicName: topic}).Context(ctx).Do()
	if err != nil {
		return "", time.Time{}, err
	}
	return strconv.FormatUint(w.HistoryId, 10), time.UnixMilli(w.Expiration), nil
}

func (l *Live) Stop(ctx context.Context) error {
	return l.svc.Users.Stop("me").Context(ctx).Do()
}

func (l *Live) History(ctx context.Context, startID string) ([]mail.Message, string, error) {
	id, err := strconv.ParseUint(startID, 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("history id: %w", err)
	}
	var ids []string
	var latest string
	var page string
	for n := 0; n < 10; n++ {
		call := l.svc.Users.History.List("me").Context(ctx).StartHistoryId(id).HistoryTypes("messageAdded").MaxResults(100)
		if page != "" {
			call = call.PageToken(page)
		}
		resp, err := call.Do()
		if err != nil {
			var ge *googleapi.Error
			if errors.As(err, &ge) && ge.Code == 404 {
				return nil, "", ErrHistoryGone
			}
			return nil, "", err
		}
		if resp.HistoryId != 0 {
			latest = strconv.FormatUint(resp.HistoryId, 10)
		}
		for _, h := range resp.History {
			for _, added := range h.MessagesAdded {
				if added.Message != nil && added.Message.Id != "" {
					ids = append(ids, added.Message.Id)
				}
			}
		}
		if resp.NextPageToken == "" {
			break
		}
		page = resp.NextPageToken
	}
	return l.fetchAll(ctx, ids), latest, nil
}

func (l *Live) ListSince(ctx context.Context, since time.Time, limit int) ([]mail.Message, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := fmt.Sprintf("after:%d", since.Unix())
	var ids []string
	var page string
	for len(ids) < limit {
		call := l.svc.Users.Messages.List("me").Context(ctx).Q(q).MaxResults(100)
		if page != "" {
			call = call.PageToken(page)
		}
		resp, err := call.Do()
		if err != nil {
			return nil, err
		}
		for _, m := range resp.Messages {
			ids = append(ids, m.Id)
			if len(ids) >= limit {
				break
			}
		}
		if resp.NextPageToken == "" {
			break
		}
		page = resp.NextPageToken
	}
	return l.fetchAll(ctx, ids), nil
}

func (l *Live) fetchAll(ctx context.Context, ids []string) []mail.Message {
	seen := map[string]bool{}
	var out []mail.Message
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		m, err := l.Get(ctx, id)
		if err != nil {
			continue
		}
		out = append(out, m)
	}
	return out
}

func (l *Live) Get(ctx context.Context, id string) (mail.Message, error) {
	g, err := l.svc.Users.Messages.Get("me", id).Format("full").Context(ctx).Do()
	if err != nil {
		return mail.Message{}, err
	}
	return fromGmail(g), nil
}

func fromGmail(g *gmail.Message) mail.Message {
	var headers []*gmail.MessagePartHeader
	if g.Payload != nil {
		headers = g.Payload.Headers
	}
	m := mail.Message{
		ID: g.Id, ThreadID: g.ThreadId, HistoryID: strconv.FormatUint(g.HistoryId, 10),
		From: header(headers, "From"), To: header(headers, "To"), Cc: header(headers, "Cc"),
		Subject: header(headers, "Subject"), Snippet: g.Snippet, Labels: append([]string{}, g.LabelIds...),
	}
	if g.InternalDate != 0 {
		m.Date = time.UnixMilli(g.InternalDate).UTC()
	}
	var plain string
	var att bool
	walk(g.Payload, &plain, &att)
	if len(plain) > 200_000 {
		plain = plain[:200_000]
	}
	m.Plain = plain
	m.HasAttachment = att
	m.Category = mail.CategoryFromLabels(m.Labels)
	return m
}

func walk(p *gmail.MessagePart, plain *string, att *bool) {
	if p == nil {
		return
	}
	if p.Filename != "" || (p.Body != nil && p.Body.AttachmentId != "") {
		*att = true
	}
	if *plain == "" && strings.EqualFold(p.MimeType, "text/plain") && p.Body != nil && p.Body.Data != "" {
		if b, err := base64.RawURLEncoding.DecodeString(p.Body.Data); err == nil {
			*plain = string(b)
		} else if b, err := base64.URLEncoding.DecodeString(p.Body.Data); err == nil {
			*plain = string(b)
		}
	}
	for _, c := range p.Parts {
		walk(c, plain, att)
	}
}

func header(hs []*gmail.MessagePartHeader, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func (l *Live) Labels(ctx context.Context) ([]Label, error) {
	resp, err := l.svc.Users.Labels.List("me").Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	var out []Label
	for _, l := range resp.Labels {
		out = append(out, Label{ID: l.Id, Name: l.Name})
	}
	return out, nil
}

func (l *Live) CreateLabel(ctx context.Context, name string) (Label, error) {
	created, err := l.svc.Users.Labels.Create("me", &gmail.Label{
		Name: name, LabelListVisibility: "labelShow", MessageListVisibility: "show",
	}).Context(ctx).Do()
	if err != nil {
		return Label{}, err
	}
	return Label{ID: created.Id, Name: created.Name}, nil
}

func (l *Live) AddLabels(ctx context.Context, messageID string, labelIDs []string) error {
	_, err := l.svc.Users.Messages.Modify("me", messageID, &gmail.ModifyMessageRequest{AddLabelIds: labelIDs}).Context(ctx).Do()
	return err
}

func (l *Live) CreateFilter(ctx context.Context, f Filter) error {
	_, err := l.svc.Users.Settings.Filters.Create("me", &gmail.Filter{
		Criteria: &gmail.FilterCriteria{From: f.From, Subject: f.Subject, Query: f.Query},
		Action:   &gmail.FilterAction{AddLabelIds: []string{f.AddLabel}},
	}).Context(ctx).Do()
	return err
}
