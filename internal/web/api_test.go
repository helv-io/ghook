package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/helv-io/ghook/internal/store"
)

type apiResult struct {
	Code  int
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error string          `json:"error"`
	Field string          `json:"field"`
}

func callAPI(t *testing.T, srv *Server, method, path, token, body string) apiResult {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	out := apiResult{Code: rec.Code}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: bad JSON %q", method, path, rec.Body.String())
		}
	}
	out.Code = rec.Code
	return out
}

func mintKey(t *testing.T, db *store.DB, scope string) string {
	t.Helper()
	_, token, err := db.CreateAPIKey("script", scope)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestAPIAuth(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, _ := loginAs(t, srv, db, "u-1", "ada@example.com", "Ada")
	token := mintKey(t, scoped, store.ScopeRead)

	if r := callAPI(t, srv, "GET", "/api/v1/status", "", ""); r.Code != http.StatusUnauthorized || r.OK {
		t.Fatalf("missing key: %d", r.Code)
	}
	if r := callAPI(t, srv, "GET", "/api/v1/status", "ghk_00000000_"+strings.Repeat("a", 43), ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("unknown key: %d", r.Code)
	}
	if r := callAPI(t, srv, "GET", "/api/v1/status", token[:len(token)-1]+"x", ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("tampered key: %d", r.Code)
	}
	if r := callAPI(t, srv, "GET", "/api/v1/status", token, ""); r.Code != http.StatusOK || !r.OK {
		t.Fatalf("valid key: %d %s", r.Code, r.Error)
	}

	// A session cookie is not an API credential.
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie accepted on the API: %d", rec.Code)
	}
	// Nor is a key in the query string, even with a valid header.
	if r := callAPI(t, srv, "GET", "/api/v1/status?access_token="+url.QueryEscape(token), "", ""); r.Code != http.StatusBadRequest {
		t.Fatalf("query key: %d", r.Code)
	}
	if r := callAPI(t, srv, "GET", "/api/v1/status?x="+url.QueryEscape(token), token, ""); r.Code != http.StatusBadRequest {
		t.Fatalf("key in query with header: %d", r.Code)
	}

	// Read-only keys cannot write.
	if r := callAPI(t, srv, "POST", "/api/v1/targets", token, `{"name":"ops","url":"https://example.com/hook"}`); r.Code != http.StatusForbidden {
		t.Fatalf("read-only write: %d", r.Code)
	}
	if n := scoped.TargetCount(); n != 0 {
		t.Fatalf("read-only key created a target")
	}

	// Revoked keys stop working.
	keys, _ := scoped.APIKeys()
	if _, err := scoped.RevokeAPIKey(keys[0].ID); err != nil {
		t.Fatal(err)
	}
	if r := callAPI(t, srv, "GET", "/api/v1/status", token, ""); r.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key: %d", r.Code)
	}

	// The key is stored hashed.
	var stored int
	_ = db.SQL.QueryRow(`SELECT count(*) FROM api_keys WHERE hash LIKE ?`, "%"+token[13:]+"%").Scan(&stored)
	if stored != 0 {
		t.Fatal("token stored in the clear")
	}
}

func TestAPICrossTenant(t *testing.T) {
	srv, db := testServer(t)
	_, a, _ := loginAs(t, srv, db, "u-a", "ada@example.com", "Ada")
	_, b, _ := loginAs(t, srv, db, "u-b", "bob@example.com", "Bob")
	tg, err := a.SaveTarget(store.Target{Name: "ops", URL: "https://example.com/hook", AuthMode: "bearer"}, "s3cret", false)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := a.SaveRoute(store.Route{Name: "all", Enabled: true, Fallback: true, TargetID: tg.ID})
	if err != nil {
		t.Fatal(err)
	}
	keyB := mintKey(t, b, store.ScopeWrite)
	keysA, _ := a.APIKeys()
	_ = keysA

	var list []json.RawMessage
	r := callAPI(t, srv, "GET", "/api/v1/targets", keyB, "")
	_ = json.Unmarshal(r.Data, &list)
	if r.Code != 200 || len(list) != 0 {
		t.Fatalf("B sees A's targets: %d %s", r.Code, r.Data)
	}
	for _, c := range []struct{ m, p, body string }{
		{"GET", "/api/v1/targets/" + itoa(tg.ID), ""},
		{"PATCH", "/api/v1/targets/" + itoa(tg.ID), `{"name":"x"}`},
		{"DELETE", "/api/v1/targets/" + itoa(tg.ID), ""},
		{"GET", "/api/v1/routes/" + itoa(rt.ID), ""},
		{"PATCH", "/api/v1/routes/" + itoa(rt.ID), `{"name":"x"}`},
		{"DELETE", "/api/v1/routes/" + itoa(rt.ID), ""},
		{"POST", "/api/v1/targets/" + itoa(tg.ID) + "/pause", `{"paused":true}`},
	} {
		if r := callAPI(t, srv, c.m, c.p, keyB, c.body); r.Code != http.StatusNotFound {
			t.Fatalf("%s %s as B: %d", c.m, c.p, r.Code)
		}
	}
	// B cannot point a route at A's target.
	if r := callAPI(t, srv, "POST", "/api/v1/routes", keyB, `{"name":"steal","target_id":`+itoa(tg.ID)+`}`); r.Code != http.StatusBadRequest {
		t.Fatalf("route to a foreign target: %d", r.Code)
	}
	// B cannot revoke A's keys.
	_, _, _ = a.CreateAPIKey("a-key", store.ScopeRead)
	ka, _ := a.APIKeys()
	if r := callAPI(t, srv, "DELETE", "/api/v1/account/keys/"+itoa(ka[0].ID), keyB, ""); r.Code != http.StatusNotFound {
		t.Fatalf("B revoked A's key: %d", r.Code)
	}
	if got, _, _ := a.TargetByID(tg.ID, false); got.Name != "ops" || got.Paused {
		t.Fatalf("A's target changed: %+v", got)
	}
	if _, ok, _ := a.RouteByID(rt.ID); !ok {
		t.Fatal("A's route deleted")
	}
}

func TestAPIRoundTrip(t *testing.T) {
	srv, db := testServer(t)
	_, scoped, _ := loginAs(t, srv, db, "u-1", "ada@example.com", "Ada")
	key := mintKey(t, scoped, store.ScopeWrite)
	must := func(r apiResult, want int, what string) apiResult {
		t.Helper()
		if r.Code != want {
			t.Fatalf("%s: %d %s", what, r.Code, r.Error)
		}
		return r
	}
	var tv targetView
	r := must(callAPI(t, srv, "POST", "/api/v1/targets", key, `{"name":"ops","url":"https://example.com/hook","secret":"s3cret"}`), 201, "create target")
	_ = json.Unmarshal(r.Data, &tv)
	if !tv.HasSecret || strings.Contains(string(r.Data), "s3cret") {
		t.Fatalf("target secret: %s", r.Data)
	}
	must(callAPI(t, srv, "POST", "/api/v1/targets", key, `{"name":"bad","url":"ftp://x"}`), 400, "bad url")
	r = must(callAPI(t, srv, "PATCH", "/api/v1/targets/"+itoa(tv.ID), key, `{"rate_per_minute":5}`), 200, "patch target")
	_ = json.Unmarshal(r.Data, &tv)
	if tv.RatePerMin != 5 || tv.URL != "https://example.com/hook" || !tv.HasSecret {
		t.Fatalf("patch lost fields: %+v", tv)
	}
	must(callAPI(t, srv, "POST", "/api/v1/targets/"+itoa(tv.ID)+"/pause", key, `{"paused":true}`), 200, "pause target")
	if got, _, _ := scoped.TargetByID(tv.ID, false); !got.Paused {
		t.Fatal("not paused")
	}

	var rv routeView
	r = must(callAPI(t, srv, "POST", "/api/v1/routes", key, `{"name":"billing","target":"ops","match":{"from":["billing.example.com"]}}`), 201, "create route")
	_ = json.Unmarshal(r.Data, &rv)
	if rv.TargetID != tv.ID || !rv.Enabled || len(rv.Match.From) != 1 {
		t.Fatalf("route: %+v", rv)
	}
	must(callAPI(t, srv, "POST", "/api/v1/routes", key, `{"name":"x","target_id":`+itoa(tv.ID)+`,"match":{"subject":"("}}`), 400, "bad regex")
	r = must(callAPI(t, srv, "POST", "/api/v1/routes", key, `{"name":"rest","target_id":`+itoa(tv.ID)+`,"fallback":true}`), 201, "second route")
	var rv2 routeView
	_ = json.Unmarshal(r.Data, &rv2)
	must(callAPI(t, srv, "PATCH", "/api/v1/routes/"+itoa(rv.ID), key, `{"enabled":false}`), 200, "patch route")
	if got, _, _ := scoped.RouteByID(rv.ID); got.Enabled || got.Name != "billing" {
		t.Fatalf("patch route: %+v", got)
	}
	r = must(callAPI(t, srv, "PUT", "/api/v1/routes/"+itoa(rv.ID)+"/fields/from", key, `{"values":["b.example.com","a.example.com"]}`), 200, "field")
	if !strings.Contains(string(r.Data), "a.example.com") {
		t.Fatalf("field: %s", r.Data)
	}
	must(callAPI(t, srv, "PUT", "/api/v1/routes/order", key, `{"ids":[`+itoa(rv2.ID)+`,`+itoa(rv.ID)+`]}`), 200, "order")
	if rs, _ := scoped.Routes(); rs[0].ID != rv2.ID {
		t.Fatal("order not saved")
	}
	must(callAPI(t, srv, "POST", "/api/v1/routes/"+itoa(rv.ID)+"/move", key, `{"dir":"up"}`), 200, "move")
	if rs, _ := scoped.Routes(); rs[0].ID != rv.ID {
		t.Fatal("move not saved")
	}
	must(callAPI(t, srv, "GET", "/api/v1/routes/simulate?n=5", key, ""), 200, "simulate")
	must(callAPI(t, srv, "POST", "/api/v1/routes/preview", key, `{"name":"p","target":"ops"}`), 200, "preview")

	r = must(callAPI(t, srv, "PATCH", "/api/v1/settings", key, `{"timezone":"America/New_York","testing_mode":true,"retention_days":7}`), 200, "settings")
	if scoped.Setting("timezone", "") != "America/New_York" || !scoped.BoolSetting("testing_mode", false) || scoped.IntSetting("retention_days", 0) != 7 {
		t.Fatalf("settings: %s", r.Data)
	}
	must(callAPI(t, srv, "PATCH", "/api/v1/settings", key, `{"timezone":"Mars/Base"}`), 400, "bad timezone")
	must(callAPI(t, srv, "PATCH", "/api/v1/settings", key, `{"nope":1}`), 400, "unknown setting")

	r = must(callAPI(t, srv, "GET", "/api/v1/export?format=json", key, ""), 200, "export")
	if !strings.Contains(string(r.Data), "billing") {
		t.Fatalf("export: %s", r.Data)
	}
	must(callAPI(t, srv, "POST", "/api/v1/import", key, `{"version":1,"targets":[{"name":"ops2","url":"https://example.com/two"}]}`), 200, "import")
	if _, ok, _ := scoped.TargetByName("ops2", false); !ok {
		t.Fatal("import did not create the target")
	}

	r = must(callAPI(t, srv, "GET", "/api/v1/status", key, ""), 200, "status")
	var st struct {
		Routes  map[string]int `json:"routes"`
		Targets map[string]int `json:"targets"`
	}
	_ = json.Unmarshal(r.Data, &st)
	if st.Routes["total"] != 2 || st.Targets["total"] != 2 || st.Routes["filters"] < 2 {
		t.Fatalf("status: %s", r.Data)
	}

	must(callAPI(t, srv, "DELETE", "/api/v1/targets/"+itoa(tv.ID), key, ""), 409, "delete used target")
	must(callAPI(t, srv, "DELETE", "/api/v1/routes/"+itoa(rv.ID), key, ""), 200, "delete route")
	must(callAPI(t, srv, "DELETE", "/api/v1/routes/"+itoa(rv2.ID), key, ""), 200, "delete route 2")
	must(callAPI(t, srv, "DELETE", "/api/v1/targets/"+itoa(tv.ID), key, ""), 200, "delete target")
	must(callAPI(t, srv, "GET", "/api/v1/targets/"+itoa(tv.ID), key, ""), 404, "deleted target")

	// Keys over the API: create, use, revoke.
	r = must(callAPI(t, srv, "POST", "/api/v1/account/keys", key, `{"name":"ci","scope":"read-only"}`), 201, "create key")
	var kv keyView
	_ = json.Unmarshal(r.Data, &kv)
	if !strings.HasPrefix(kv.Token, "ghk_") || kv.Scope != "read-only" {
		t.Fatalf("key: %+v", kv)
	}
	must(callAPI(t, srv, "GET", "/api/v1/account", kv.Token, ""), 200, "new key works")
	r = must(callAPI(t, srv, "GET", "/api/v1/account/keys", key, ""), 200, "list keys")
	if strings.Contains(string(r.Data), kv.Token) {
		t.Fatal("token listed again")
	}
	must(callAPI(t, srv, "DELETE", "/api/v1/account/keys/"+itoa(kv.ID), key, ""), 200, "revoke key")
	must(callAPI(t, srv, "GET", "/api/v1/account", kv.Token, ""), 401, "revoked key")

	// Writes through a key are audited.
	r = must(callAPI(t, srv, "GET", "/api/v1/audit", key, ""), 200, "audit")
	for _, want := range []string{"apikey.use", "apikey.create", "apikey.revoke", "route.save"} {
		if !strings.Contains(string(r.Data), want) {
			t.Fatalf("audit is missing %s", want)
		}
	}
	must(callAPI(t, srv, "GET", "/api/v1/nope", key, ""), 404, "unknown endpoint")
	must(callAPI(t, srv, "DELETE", "/api/v1/account", key, `{}`), 400, "delete without confirm")
}

func TestAccountPageKeys(t *testing.T) {
	srv, db := testServer(t)
	ck, scoped, _ := loginAs(t, srv, db, "u-1", "ada@example.com", "Ada")
	csrf, _ := srv.Session(reqWith(ck))
	form := url.Values{"csrf": {csrf}, "name": {"laptop"}, "scope": {"write"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/account/keys", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || strings.Contains(rec.Header().Get("Location"), "ghk_") {
		t.Fatalf("create: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Value, "ghk_") {
			t.Fatal("key put in a cookie")
		}
	}
	body := read(t, get(srv, "/admin/account", ck))
	i := strings.Index(body, `data-copy-text="ghk_`)
	if i < 0 {
		t.Fatalf("new key not shown\n%s", clip(body))
	}
	token := body[i+len(`data-copy-text="`):]
	token = token[:strings.IndexByte(token, '"')]
	if r := callAPI(t, srv, "GET", "/api/v1/status", token, ""); r.Code != 200 {
		t.Fatalf("UI key does not work: %d", r.Code)
	}
	if again := read(t, get(srv, "/admin/account", ck)); strings.Contains(again, token) {
		t.Fatal("key shown twice")
	}
	keys, _ := scoped.APIKeys()
	if len(keys) != 1 || keys[0].Scope != store.ScopeWrite || keys[0].LastUsed == 0 {
		t.Fatalf("keys: %+v", keys)
	}
	form = url.Values{"csrf": {csrf}, "id": {itoa(keys[0].ID)}}
	req = httptest.NewRequest(http.MethodPost, "/admin/account/keys/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(ck)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if r := callAPI(t, srv, "GET", "/api/v1/status", token, ""); r.Code != 401 {
		t.Fatalf("revoked UI key still works: %d", r.Code)
	}
}

func TestAPIRateLimit(t *testing.T) {
	srv, db := testServer(t)
	for i := 0; i < apiFailPerMinute; i++ {
		callAPI(t, srv, "GET", "/api/v1/status", "ghk_bad", "")
	}
	_, scoped, _ := loginAs(t, srv, db, "u-1", "ada@example.com", "Ada")
	key := mintKey(t, scoped, store.ScopeRead)
	if r := callAPI(t, srv, "GET", "/api/v1/status", key, ""); r.Code != http.StatusTooManyRequests {
		t.Fatalf("failed-auth limit: %d", r.Code)
	}
}
