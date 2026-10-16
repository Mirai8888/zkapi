// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/lab"
)

func run(ctx context.Context, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "peer":
			if len(args) != 1 {
				return errors.New("peer accepts its configuration on stdin only")
			}
			return lab.RunPeer(ctx, os.Stdin, os.Stdout)
		case "compare":
			return compare(ctx, args[1:])
		case "reference-check":
			if len(args) != 1 {
				return errors.New("reference-check accepts no arguments")
			}
			return json.NewEncoder(os.Stdout).Encode(lab.KatzenpostReferenceStatus())
		}
	}
	if len(args) == 0 || args[0] != "demo" {
		return errors.New("usage: research-mixnet demo | compare | reference-check; headless synthetic experiments only")
	}
	cfg := lab.DefaultConfig()
	f := flag.NewFlagSet("demo", flag.ContinueOnError)
	f.IntVar(&cfg.Clients, "clients", cfg.Clients, "synthetic clients (1–4)")
	f.IntVar(&cfg.Jobs, "jobs", cfg.Jobs, "synthetic jobs (0–8; zero tests idle cover)")
	f.IntVar(&cfg.Rate, "rate", cfg.Rate, "fixed cells/sec per client direction (1–20)")
	f.DurationVar(&cfg.Duration, "duration", cfg.Duration, "fixed experiment epoch (3–30s)")
	f.DurationVar(&cfg.MeanDelay, "mean-delay", cfg.MeanDelay, "mean residence time, capped at eight times the mean (0–250ms)")
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments; the demo accepts no prompts or credentials")
	}
	report, err := lab.Run(ctx, cfg)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}
	if report.Completed != report.Submitted {
		return errors.New("epoch ended before all synthetic replies arrived; inspect load and latency, not a production transport")
	}
	return nil
}

func compare(ctx context.Context, args []string) error {
	cfg := lab.DefaultCompareConfig()
	f := flag.NewFlagSet("compare", flag.ContinueOnError)
	f.IntVar(&cfg.Clients, "clients", cfg.Clients, "separate synthetic client processes (2–32)")
	f.IntVar(&cfg.Jobs, "jobs-per-client", cfg.Jobs, "sequential synthetic jobs per client (2–8)")
	f.IntVar(&cfg.Rate, "rate", cfg.Rate, "covered cells/sec per client direction (clients × rate <= 100)")
	f.DurationVar(&cfg.Duration, "duration", cfg.Duration, "fixed epoch per backend/case (3–60s)")
	f.DurationVar(&cfg.MeanDelay, "mean-delay", cfg.MeanDelay, "mean residence time in prototype relays")
	f.DurationVar(&cfg.ResponseDelay, "response-delay", cfg.ResponseDelay, "maximum synthetic provider watermark delay")
	f.IntVar(&cfg.LossPermille, "loss-permille", cfg.LossPermille, "loss at worker ingress in loss cases (20 = 2%)")
	f.IntVar(&cfg.DisconnectClients, "disconnect-clients", cfg.DisconnectClients, "clients that disconnect one-third into disconnect cases")
	f.Uint64Var(&cfg.Seed, "seed", cfg.Seed, "public workload/fault seed; not cryptographic entropy")
	cases := f.String("cases", strings.Join(cfg.Cases, ","), "comma-separated clean,watermark,loss,disconnect")
	output := f.String("output-dir", "", "write aggregate report.json and report.md here; no raw observations")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected comparison arguments")
	}
	cfg.Cases = strings.Split(*cases, ",")
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	report, err := lab.Compare(ctx, cfg, executable, []string{"peer"}, os.Stderr)
	if err != nil {
		return err
	}
	if *output != "" {
		if err := os.MkdirAll(*output, 0755); err != nil {
			return errors.New("cannot create report directory")
		}
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*output, "report.json"), append(raw, '\n'), 0644); err != nil {
			return errors.New("cannot write aggregate JSON report")
		}
		if err := os.WriteFile(filepath.Join(*output, "report.md"), []byte(lab.ComparisonMarkdown(report)), 0644); err != nil {
			return errors.New("cannot write aggregate Markdown report")
		}
	}
	return lab.WriteComparison(os.Stdout, report)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "research-mixnet:", err)
		os.Exit(1)
	}
}
