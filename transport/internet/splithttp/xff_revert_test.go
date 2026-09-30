package splithttp_test

import (
	"context"
	"io"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// runXHRemoteAddrProbe starts an XHTTP listener that echoes back the remote
// address xray attributes to the connection, then dials it with the given
// socket settings and returns that address.
func runXHRemoteAddrProbe(t *testing.T, serverSockopt *internet.SocketConfig) string {
	t.Helper()

	listenPort := tcp.PickPort()
	streamCfg := &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{Path: "sh"},
	}
	if serverSockopt != nil {
		streamCfg.SocketSettings = serverSockopt
	}

	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, streamCfg,
		func(conn stat.Connection) {
			go func(c stat.Connection) {
				defer c.Close()
				var b [1024]byte
				if _, err := c.Read(b[:]); err != nil {
					return
				}
				// Echo the address the server believes this peer has.
				common.Must2(c.Write([]byte(c.RemoteAddr().String())))
			}(conn)
		})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(),
		net.TCPDestination(net.DomainAddress("localhost"), listenPort),
		&internet.MemoryStreamConfig{
			ProtocolName:     "splithttp",
			ProtocolSettings: &Config{Path: "sh", Headers: map[string]string{"X-Forwarded-For": "1.1.1.1"}},
		})
	common.Must(err)
	defer conn.Close()

	_, err = conn.Write([]byte("probe"))
	common.Must(err)

	var b [1024]byte
	n, _ := io.ReadFull(conn, b[:])
	return string(b[:n])
}

// TestXH_XFFHonoredWhenUnconfigured covers the #6309 revert at the XHTTP call
// site: with no "sockopt.trustedXForwardedFor" configured, X-Forwarded-For is
// trusted implicitly (pre-v26.6.18 behavior) and overrides the real peer
// address. Upstream v26.9.9 ignores the header in this case.
func TestXH_XFFHonoredWhenUnconfigured(t *testing.T) {
	got := runXHRemoteAddrProbe(t, nil)
	if got != "1.1.1.1:0" {
		t.Fatalf("expected X-Forwarded-For to be honored, server saw %q", got)
	}
}

// TestXH_XFFRejectedWhenConfiguredButAbsent ensures the revert did not also
// restore unconditional trust: when trustedXForwardedFor is configured but the
// named header is missing, the header must be ignored and the real peer used.
func TestXH_XFFRejectedWhenConfiguredButAbsent(t *testing.T) {
	got := runXHRemoteAddrProbe(t, &internet.SocketConfig{
		TrustedXForwardedFor: []string{"X-Trusted-CDN"},
	})
	if got == "1.1.1.1:0" {
		t.Fatal("forged X-Forwarded-For was trusted although trustedXForwardedFor was configured")
	}
	if got == "" {
		t.Fatal("no response from XHTTP listener")
	}
}
