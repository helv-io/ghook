package web

import (
	"strings"
	"testing"
)

func TestWordmark(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"nothing here", "nothing here"},
		{"administer ghook.", `administer <span class="gh-word">ghook</span>.`},
		{"Ghook is self-hosted", `<span class="gh-word">ghook</span> is self-hosted`},
		{"ghook's access", `<span class="gh-word">ghook</span>&#39;s access`},
		{"Ghook does not sell data. Ghook does not share data.",
			`<span class="gh-word">ghook</span> does not sell data. <span class="gh-word">ghook</span> does not share data.`},
		{`<script>ghook</script>`, `&lt;script&gt;<span class="gh-word">ghook</span>&lt;/script&gt;`},
	}
	for _, c := range cases {
		got := string(wordmark(c.in))
		if got != c.want {
			t.Errorf("wordmark(%q)=\n  %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestPathcodeWrapsAtSlash(t *testing.T) {
	got := string(pathcode("ghook/Routed/<target>"))
	if !strings.Contains(got, `class="path"`) || !strings.Contains(got, `<wbr>`) || !strings.Contains(got, `path-seg`) {
		t.Fatalf("got %s", got)
	}
	if strings.Contains(got, "ghook/Routed") && !strings.Contains(got, "/<wbr>") {
		t.Fatal("missing slash wbr")
	}
}
