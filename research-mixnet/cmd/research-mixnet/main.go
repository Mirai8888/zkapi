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
	"syscall"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/lab"
)

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "demo" {
		return errors.New("usage: research-mixnet demo [--duration 6s] [--clients 2] [--jobs 2] [--rate 8] [--mean-delay 50ms]; synthetic loopback only")
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

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "research-mixnet:", err)
		os.Exit(1)
	}
}
