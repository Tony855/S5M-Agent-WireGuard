package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
	"github.com/Tony855/S5M-Agent-WireGuard/internal/secret"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wg-agent <version|config-validate|keygen>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		dataDir := fs.String("data-dir", "/data", "persistent data directory")
		output := fs.String("output", "secrets/private.key", "relative output path inside data directory")
		_ = fs.Parse(os.Args[2:])
		if err := secret.GeneratePrivateKey(*dataDir, *output); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("WireGuard private key generated; key material was not displayed.")
	case "config-validate":
		fs := flag.NewFlagSet("config-validate", flag.ExitOnError)
		path := fs.String("config", "/data/config.yaml", "path to WireGuard YAML config")
		_ = fs.Parse(os.Args[2:])
		cfg, err := config.Load(*path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		result := map[string]any{
			"valid": true, "apiVersion": cfg.APIVersion, "interface": cfg.Interface.Name,
			"role": cfg.Interface.Role, "backend": cfg.Interface.Backend, "peerCount": len(cfg.Peers),
		}
		_ = json.NewEncoder(os.Stdout).Encode(result)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(2)
	}
}
