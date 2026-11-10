package runtime

import (
	"context"
	"time"

	"github.com/Tony855/S5M-Agent-WireGuard/internal/config"
)

type Capabilities struct {
	Backend        string   `json:"backend"`
	Available      bool     `json:"available"`
	SupportsClient bool     `json:"supportsClient"`
	SupportsServer bool     `json:"supportsServer"`
	Features       []string `json:"features,omitempty"`
	Reason         string   `json:"reason,omitempty"`
}

type PeerStatus struct {
	PublicKey            string     `json:"publicKey"`
	Endpoint             string     `json:"endpoint,omitempty"`
	AllowedIPs           []string   `json:"allowedIPs,omitempty"`
	LastHandshake        *time.Time `json:"lastHandshake,omitempty"`
	ReceiveBytes         uint64     `json:"receiveBytes"`
	TransmitBytes        uint64     `json:"transmitBytes"`
	PersistentKeepalive  int        `json:"persistentKeepalive,omitempty"`
}

type Status struct {
	Interface  string       `json:"interface"`
	Backend    string       `json:"backend"`
	Running    bool         `json:"running"`
	ListenPort int          `json:"listenPort,omitempty"`
	Peers      []PeerStatus `json:"peers,omitempty"`
	LastError  string       `json:"lastError,omitempty"`
}

type Runtime interface {
	Probe(context.Context) Capabilities
	Apply(context.Context, config.Config) error
	Status(context.Context, string) (Status, error)
	Stop(context.Context, string) error
}
