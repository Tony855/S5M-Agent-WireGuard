package routeros

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRESTClientUsesHTTPSBasicAuthAndFixedReadResources(t *testing.T) {
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "s5m-monitor" || pass != "router-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		seen = append(seen, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rest/system/resource":
			_, _ = w.Write([]byte(`{"version":"7.26","board-name":"hAP"}`))
		case "/rest/interface/wireguard":
			_, _ = w.Write([]byte(`[{"name":"wg-s5m","running":"true","listen-port":"51820"}]`))
		case "/rest/interface/wireguard/peers":
			_, _ = w.Write([]byte(`[]`))
		case "/rest/ip/address":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewRESTClient(server.URL, "s5m-monitor", "router-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	resource, err := client.SystemResource(context.Background())
	if err != nil || resource["version"] != "7.26" {
		t.Fatalf("resource=%v err=%v", resource, err)
	}
	interfaces, err := client.WireGuardInterfaces(context.Background())
	if err != nil || len(interfaces) != 1 || interfaces[0]["name"] != "wg-s5m" {
		t.Fatalf("interfaces=%v err=%v", interfaces, err)
	}
	if _, err := client.WireGuardPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.IPAddresses(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "/rest/system/resource,/rest/interface/wireguard,/rest/interface/wireguard/peers,/rest/ip/address" {
		t.Fatalf("unexpected REST paths: %v", seen)
	}
}

func TestRESTClientRejectsInsecureOrAmbiguousEndpoints(t *testing.T) {
	cases := []string{
		"http://192.0.2.1",
		"https://user:pass@192.0.2.1",
		"https://192.0.2.1/rest?foo=bar",
		"https://192.0.2.1/rest#fragment",
		"https://192.0.2.1/other",
	}
	for _, endpoint := range cases {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := NewRESTClient(endpoint, "monitor", "secret", nil); err == nil {
				t.Fatal("unsafe RouterOS endpoint accepted")
			}
		})
	}
}

func TestRESTClientDoesNotFollowRedirectsOrLeakCredentials(t *testing.T) {
	var redirected bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
	}))
	defer target.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/rest/system/resource", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	client, err := NewRESTClient(origin.URL, "monitor", "secret", origin.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SystemResource(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect response error = %v", err)
	}
	if redirected {
		t.Fatal("RouterOS REST client followed redirect with Basic credentials")
	}
}

func TestRESTClientBoundsResponsesAndRedactsErrorBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("sensitive-router-password"))
	}))
	defer server.Close()
	client, err := NewRESTClient(server.URL, "monitor", "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SystemResource(context.Background())
	if err == nil || strings.Contains(err.Error(), "sensitive-router-password") {
		t.Fatalf("RouterOS error body was exposed: %v", err)
	}
}

func TestRESTClientRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"value":"`+strings.Repeat("x", maxRESTResponseBytes)+`"}`)
	}))
	defer server.Close()
	client, err := NewRESTClient(server.URL, "monitor", "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SystemResource(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("oversized RouterOS response error = %v", err)
	}
}
