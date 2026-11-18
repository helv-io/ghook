package auth

import "testing"

func TestDisplay(t *testing.T) {
	cases := []struct {
		in   Identity
		want string
	}{
		{Identity{Username: "ada", Email: "ada@example.com", Name: "Ada", Subject: "sub"}, "ada"},
		{Identity{Email: "ada@example.com", Name: "Ada", Subject: "sub"}, "ada@example.com"},
		{Identity{Name: "Ada", Subject: "sub"}, "Ada"},
		{Identity{Subject: "sub"}, "sub"},
	}
	for _, c := range cases {
		if got := c.in.Display(); got != c.want {
			t.Fatalf("%+v: got %q want %q", c.in, got, c.want)
		}
	}
}
