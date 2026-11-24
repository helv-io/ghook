package bundle

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/helv-io/ghook/internal/match"
	"github.com/helv-io/ghook/internal/secrets"
	"github.com/helv-io/ghook/internal/store"
)

func TestExportOmitsSecretsUnlessSealed(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "g.db"), "", filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tg, err := db.SaveTarget(store.Target{Name: "ops", URL: "https://bot.example.com/hook", AuthMode: "bearer"}, "hidden", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveRoute(store.Route{Name: "primary", Enabled: true, Fallback: true, TargetID: tg.ID, Spec: match.Spec{Categories: []string{"primary"}}}); err != nil {
		t.Fatal(err)
	}
	raw, err := Export(db, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hidden") {
		t.Fatalf("secret leaked:\n%s", raw)
	}
	sealed, err := Export(db, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sealed), "enc:v1:") || strings.Contains(string(sealed), "hidden") {
		t.Fatalf("expected sealed secret, got\n%s", sealed)
	}
	dir2 := t.TempDir()
	db2, err := store.Open(filepath.Join(dir2, "g.db"), "", filepath.Join(dir2, "k"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if _, err := Import(db2, sealed, "correct horse"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db2.TargetByName("ops", true)
	if err != nil || !ok || got.Secret() != "hidden" {
		t.Fatalf("imported secret %q ok %v err %v", got.Secret(), ok, err)
	}
	routes, _ := db2.Routes()
	if len(routes) != 1 || !routes[0].Fallback || len(routes[0].Spec.Categories) != 1 {
		t.Fatalf("routes %+v", routes)
	}
	box, _ := secrets.FromString("correct horse")
	if !secrets.IsSealed(box.Seal("x")) {
		t.Fatal("seal")
	}
}
