package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/agent"
	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
	"github.com/Tony855/S5M-Agent-WireGuard/internal/runtime/linux"
	"github.com/Tony855/S5M-Agent-WireGuard/internal/secret"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "keygen":
		keygen(os.Args[2:])
	case "config-validate":
		validate(os.Args[2:])
	case "apply":
		apply(os.Args[2:])
	case "status":
		status(os.Args[2:])
	case "stop":
		stop(os.Args[2:])
	case "agent-run":
		agentRun(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wg-agent <version|config-validate|keygen|apply|status|stop|agent-run>")
	os.Exit(2)
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	dataDir := fs.String("data-dir", "/data", "persistent data directory")
	output := fs.String("output", "secrets/private.key", "relative output path inside data directory")
	_ = fs.Parse(args)
	if err := secret.GeneratePrivateKey(*dataDir, *output); err != nil {
		fatal(err)
	}
	fmt.Println("WireGuard private key generated; key material was not displayed.")
}

func validate(args []string) {
	fs := flag.NewFlagSet("config-validate", flag.ExitOnError)
	path := fs.String("config", "/data/config.yaml", "path to WireGuard YAML config")
	dataDir := fs.String("data-dir", "/data", "persistent data directory for WireGuard secrets")
	_ = fs.Parse(args)
	cfg, err := config.LoadWithDataDir(*path, *dataDir)
	if err != nil {
		fatal(err)
	}
	result := map[string]any{
		"valid": true, "apiVersion": cfg.APIVersion, "interface": cfg.Interface.Name,
		"role": cfg.Interface.Role, "backend": cfg.Interface.Backend, "peerCount": len(cfg.Peers),
	}
	writeJSON(result)
}

func apply(args []string) {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	dataDir := fs.String("data-dir", "/data", "persistent data directory")
	path := fs.String("config", "/data/config.yaml", "path to WireGuard YAML config")
	_ = fs.Parse(args)
	cfg, err := config.LoadWithDataDir(*path, *dataDir)
	if err != nil {
		fatal(err)
	}
	runtime := linux.New(*dataDir)
	if err := runtime.Apply(context.Background(), cfg); err != nil {
		fatal(err)
	}
	writeJSON(map[string]any{"applied": true, "interface": cfg.Interface.Name, "backend": "linux-kernel"})
}

func status(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dataDir := fs.String("data-dir", "/data", "persistent data directory")
	name := fs.String("interface", "wg0", "WireGuard interface name")
	_ = fs.Parse(args)
	result, err := linux.New(*dataDir).Status(context.Background(), *name)
	if err != nil {
		fatal(err)
	}
	writeJSON(result)
}

func stop(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	dataDir := fs.String("data-dir", "/data", "persistent data directory")
	name := fs.String("interface", "wg0", "WireGuard interface name")
	_ = fs.Parse(args)
	if err := linux.New(*dataDir).Stop(context.Background(), *name); err != nil {
		fatal(err)
	}
	writeJSON(map[string]any{"stopped": true, "interface": *name})
}

func agentRun(args []string) {
	fs := flag.NewFlagSet("agent-run", flag.ExitOnError)
	settingsPath := fs.String("agent-config", "/data/agent.yaml", "protected Agent settings file")
	configPath := fs.String("config", "/data/config.yaml", "WireGuard YAML config")
	dataDir := fs.String("data-dir", "/data", "persistent data directory")
	_ = fs.Parse(args)
	settings, err := agent.LoadSettings(*settingsPath)
	if err != nil {
		fatal(err)
	}
	runtime := linux.New(*dataDir)
	client := &agent.Client{
		Settings: settings, SettingsPath: *settingsPath,
		Status: func(ctx context.Context) (map[string]any, error) {
			return agent.BuildWireGuardStatus(ctx, *configPath, *dataDir, version, runtime), nil
		},
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := client.Run(ctx); err != nil {
		fatal(err)
	}
}

func writeJSON(value any) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
