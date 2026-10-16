package zkapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

func (c *Client) rewritePrompt(ctx context.Context, body json.RawMessage, identity string) (json.RawMessage, error) {
	draft, err := rewriter.Select(body)
	if err != nil {
		return nil, rewriter.ErrFailed
	}
	if draft == nil {
		return body, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Only route preparation is speculative; no lease/payment is acquired until
	// rewriting succeeds. Cancellation closes the SOCKS handshake and joins it.
	var ready chan error
	if c.config.TorMode {
		ready = make(chan error, 1)
		go func() { ready <- relay.PrepareTor(ctx, c.config.TorEndpoint, c.config.InferenceBaseURL, identity) }()
	}
	rewritten, notice, err := draft.Rewrite(ctx, c.config.Rewriter)
	if err == nil {
		err = rewriter.Publish(ctx, notice)
	}
	if err != nil {
		cancel()
	}
	if ready != nil {
		routeErr := <-ready
		if err == nil && routeErr != nil {
			return nil, &Error{http.StatusBadGateway, "tor_preparation_failed"}
		}
	}
	if err != nil {
		return nil, err
	}
	return rewritten, nil
}
