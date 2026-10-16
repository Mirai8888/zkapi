package rewriter

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestLiveLocalTranscript(t *testing.T) {
	if os.Getenv("ZKAPI_TEST_REWRITER") != "1" {
		t.Skip("set ZKAPI_TEST_REWRITER=1 for localhost:8012")
	}
	c := Config{URL: "http://localhost:8012", Model: "qwen3.8-flash-next"}
	var transcript Transcript
	first := json.RawMessage(`{"messages":[{"role":"user","content":"hey, could ya explain what a hash map is? keep it to two sentences pls."}]}`)
	_, n, err := transcript.Rewrite(context.Background(), first, c)
	if err != nil {
		t.Fatal(err)
	}
	saved := string(transcript.entries[0].user)
	t.Logf("First synthetic rewrite: %q", n.Texts)
	next := json.RawMessage(`{"messages":[{"role":"user","content":"hey, could ya explain what a hash map is? keep it to two sentences pls."},{"role":"assistant","content":"A hash map stores key-value pairs using hashes for lookup."},{"role":"user","content":"ok cool, now gimme a tiny python example, no more than 5 lines tho"}]}`)
	out, n, err := transcript.Rewrite(context.Background(), next, c)
	if err != nil {
		t.Fatal(err)
	}
	var target struct{ Messages []json.RawMessage }
	if json.Unmarshal(out, &target) != nil || string(target.Messages[0]) != saved {
		t.Fatal("live continuation did not replay exact prior rewrite")
	}
	t.Logf("Second synthetic rewrite: %q", n.Texts)
	// No endpoint needed for an exact retry: both rewrites must already exist.
	c.URL = "http://127.0.0.1:1"
	retry, _, err := transcript.Rewrite(context.Background(), next, c)
	if err != nil || string(retry) != string(out) {
		t.Fatal("cached retry contacted rewriter or changed transcript", err)
	}
}
