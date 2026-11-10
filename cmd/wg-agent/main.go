package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wg-agent <version|config-validate>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
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
