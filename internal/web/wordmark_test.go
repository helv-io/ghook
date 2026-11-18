package web

import "testing"

func TestWordmark(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"nothing here", "nothing here"},
		{"administer ghook.", `administer <span class="gh-word">ghook</span>.`},
		{"Ghook is self-hosted", `<span class="gh-word">Ghook</span> is self-hosted`},
		{"ghook's access", `<span class="gh-word">ghook</span>&#39;s access`},
		{"Ghook does not sell data. Ghook does not share data.",
			`<span class="gh-word">Ghook</span> does not sell data. <span class="gh-word">Ghook</span> does not share data.`},
		{`<script>ghook</script>`, `&lt;script&gt;<span class="gh-word">ghook</span>&lt;/script&gt;`},
	}
	for _, c := range cases {
		got := string(wordmark(c.in))
		if got != c.want {
			t.Errorf("wordmark(%q)=\n  %q\nwant %q", c.in, got, c.want)
		}
	}
}
