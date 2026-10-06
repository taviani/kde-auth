package handler

import "testing"

func TestClientIDFromNext(t *testing.T) {
	if got := clientIDFromNext("/authorize?client_id=instacrane&redirect_uri=http%3A%2F%2Flocalhost"); got != "instacrane" {
		t.Fatalf("client id = %q", got)
	}
	for _, next := range []string{
		"",
		"/login",
		"https://auth.example/authorize?client_id=instacrane",
		"/authorize",
	} {
		if got := clientIDFromNext(next); got != "" {
			t.Fatalf("next %q yielded %q", next, got)
		}
	}
}
