package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/cover"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

const settingsHelp = `Saved settings (stop serve before edits; no setup or payment):
  config --vault-protocol legacy|concession|default  (use alone)
  config --model MODEL | --clear-model
  config --rewriter-url URL --rewriter-model MODEL
         [--rewriter-api-key-env ENV | --rewriter-clear-api-key]
         [--rewriter-notice reasoning|metadata|off]
  config --clear-rewriter
  config --cover-urls 'https://permitted.example/resource'
         [--cover-rate 5] [--cover-concurrency 4]
  config --clear-cover
  config                   Pretty-printed saved config (credentials redacted)
  config --setup           Explicit wallet setup/funding
These edits can include --relay-url, --key-reuse-window-seconds,
--listen and --require-api-key. Existing rewriter credentials are preserved
unless explicitly replaced or cleared. Vault changes are a separate operation.
The former set-* commands have been removed.
`

// Handle profile-only settings before protocol dispatch. The same editor serves
// both engines, even if a protocol artifact is absent; it never starts a wallet.
// Vault preference keeps its existing separately locked storage, so old profiles
// need no migration. Do not pretend two file writes are an atomic transaction.
func runConfigSettings(dir string, args []string, out io.Writer) (bool, error) {
	if len(args) == 0 {
		return true, printSavedConfig(dir, out)
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(out, settingsHelp)
		_, err := parseConfigureOptions([]string{"--help"}, out)
		if errors.Is(err, flag.ErrHelp) {
			err = nil
		}
		return true, err
	}
	selected := false
	for _, arg := range args {
		name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
		switch name {
		case "network", "zkapi-binary", "proof-setup-dir", "exit-rpc-url", "bundler-url", "withdrawal-fees", "relay-url", "listen", "require-api-key", "key-reuse-window-seconds", "status", "vault-protocol", "model", "clear-model", "rewriter-url", "rewriter-model", "rewriter-api-key-env", "rewriter-clear-api-key", "rewriter-notice", "clear-rewriter", "cover-urls", "cover-rate", "cover-concurrency", "clear-cover":
			selected = true
		}
	}
	if !selected {
		return false, nil
	}
	f := flag.NewFlagSet("config", flag.ContinueOnError)
	f.SetOutput(out)
	protocol := f.String("vault-protocol", "", "saved vault stack; use alone")
	status := f.Bool("status", false, "show all saved settings")
	model := f.String("model", "", "default target model")
	clearModel := f.Bool("clear-model", false, "clear default model")
	url := f.String("rewriter-url", "", "direct rewriter URL")
	editor := f.String("rewriter-model", "", "rewriter model")
	keyEnv := f.String("rewriter-api-key-env", "", "environment variable holding rewriter key")
	clearKey := f.Bool("rewriter-clear-api-key", false, "remove rewriter API key")
	notice := f.String("rewriter-notice", "", "reasoning, metadata or off")
	clearEditor := f.Bool("clear-rewriter", false, "disable rewriting and remove its key")
	urls := f.String("cover-urls", "", "permitted HTTPS destinations separated by spaces")
	rate := f.Float64("cover-rate", cover.DefaultRate, "mean cover arrivals per second")
	concurrency := f.Int("cover-concurrency", cover.DefaultConcurrency, "cover worker limit")
	clearCover := f.Bool("clear-cover", false, "disable cover")
	relay := f.String("relay-url", "", "saved routing endpoint")
	reuse := f.Int("key-reuse-window-seconds", config.DefaultKeyReuseWindowSeconds, "key reuse window")
	listen := f.String("listen", "", "local listener")
	requireKey := f.Bool("require-api-key", false, "require local inference key")
	oldFields := map[string]*string{}
	for _, name := range []string{"network", "zkapi-binary", "proof-setup-dir", "exit-rpc-url", "bundler-url", "withdrawal-fees"} {
		oldFields[name] = f.String(name, "", "saved "+name+" setting")
	}
	if err := f.Parse(args); err != nil {
		return true, err
	}
	if f.NArg() != 0 {
		return true, errors.New("unexpected config arguments")
	}
	seen := map[string]bool{}
	f.Visit(func(v *flag.Flag) { seen[v.Name] = true })
	if seen["status"] || seen["vault-protocol"] {
		if len(seen) != 1 {
			return true, errors.New("use --status or --vault-protocol alone; nothing saved")
		}
		if seen["vault-protocol"] {
			p := *protocol
			if p == "default" {
				p = "--clear"
			}
			return true, runSetVaultProtocol(dir, []string{p}, out)
		}
		if !*status {
			return true, errors.New("use --status without =false")
		}
		return true, printSavedConfig(dir, out)
	}
	c, err := config.Load(dir)
	if err != nil {
		return true, configurationRequired(err)
	}
	next := c
	oldArgs := []string{}
	for name, value := range oldFields {
		if seen[name] {
			oldArgs = append(oldArgs, "--"+name+"="+*value)
		}
	}
	if len(oldArgs) > 0 {
		options, err := parseConfigureOptions(oldArgs, out)
		if err != nil {
			return true, err
		}
		next = applyConfigureOptions(next, options)
	}
	if *clearModel && seen["model"] {
		return true, errors.New("use --clear-model without --model")
	}
	if seen["model"] {
		if !config.ValidModelID(*model) {
			return true, errors.New("invalid model ID; use --clear-model to remove it")
		}
		next.DefaultModel = *model
	}
	if *clearModel {
		next.DefaultModel = ""
	}
	editorEdit := seen["rewriter-url"] || seen["rewriter-model"] || seen["rewriter-api-key-env"] || seen["rewriter-clear-api-key"] || seen["rewriter-notice"]
	if *clearEditor && editorEdit {
		return true, errors.New("cannot clear and edit rewriter together")
	}
	if *clearEditor {
		next.Rewriter = rewriter.Config{}
	}
	if editorEdit {
		if !next.Rewriter.Enabled() {
			next.Rewriter.Notice = "reasoning"
		}
		if seen["rewriter-url"] {
			next.Rewriter.URL = *url
		}
		if seen["rewriter-model"] {
			next.Rewriter.Model = *editor
		}
		if seen["rewriter-notice"] {
			next.Rewriter.Notice = *notice
		}
		if *clearKey && seen["rewriter-api-key-env"] {
			return true, errors.New("cannot clear and replace rewriter key together")
		}
		if *clearKey {
			next.Rewriter.APIKey = ""
		}
		if seen["rewriter-api-key-env"] {
			key := os.Getenv(*keyEnv)
			if key == "" {
				return true, errors.New("rewriter API key environment variable is empty")
			}
			next.Rewriter.APIKey = key
		}
		if !next.Rewriter.Enabled() {
			return true, errors.New("rewriter URL and model are required; use --clear-rewriter to disable")
		}
	}
	coverEdit := seen["cover-urls"] || seen["cover-rate"] || seen["cover-concurrency"]
	if *clearCover && coverEdit {
		return true, errors.New("cannot clear and edit cover together")
	}
	if *clearCover {
		next.Cover = cover.Config{}
	}
	if coverEdit {
		if !next.Cover.Enabled() {
			next.Cover.Rate = cover.DefaultRate
			next.Cover.Concurrency = cover.DefaultConcurrency
		}
		if seen["cover-urls"] {
			next.Cover.URLs = *urls
		}
		if seen["cover-rate"] {
			next.Cover.Rate = *rate
		}
		if seen["cover-concurrency"] {
			next.Cover.Concurrency = *concurrency
		}
		if !next.Cover.Enabled() {
			return true, errors.New("cover destinations required; use --clear-cover to disable")
		}
	}
	if seen["relay-url"] {
		next.RelayURL = *relay
	}
	if seen["key-reuse-window-seconds"] {
		next.KeyReuseWindowSeconds = *reuse
	}
	if seen["listen"] {
		next.Listen = *listen
	}
	if seen["require-api-key"] {
		next.RequireAPIKey = *requireKey
	}
	saved, err := config.LoadVaultProtocol(dir)
	if err != nil {
		return true, err
	}
	if saved == "legacy" {
		if seen["zkapi-binary"] || seen["proof-setup-dir"] {
			return true, errors.New("legacy companion/setup overrides require a reviewed prepared profile; nothing saved")
		}
		if _, _, err := legacyDispatchPlan(dir, true, next, []string{"serve"}, "/unused/client"); err != nil {
			return true, err
		}
	}
	if err := config.Update(dir, c, next); err != nil {
		return true, err
	}
	fmt.Fprintln(out, "Saved settings. Restart serve to apply. No setup, network request or payment performed.")
	if next.Rewriter.Enabled() {
		fmt.Fprintln(out, "WARNING: uncached user text goes directly to the rewriter, outside Tor. Rewriting does not guarantee anonymity.")
	}
	if next.Cover.Enabled() {
		fmt.Fprintln(out, "Cover consumes bandwidth and destination resources; use only permitted URLs. IsolateSOCKSAuth is required; cover does not guarantee anonymity.")
	}
	return true, nil
}
