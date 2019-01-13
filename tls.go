// TLS utilities
package onion2web

import (
	"bytes"
	"crypto/tls"
	"net"
)

var SnakeTLS *tls.Config

const snakeCert = `
-----BEGIN CERTIFICATE-----
MIIBJTCBzaADAgECAgEAMAoGCCqGSM49BAMCMAAwHhcNMTkwMTExMTgwMDU5WhcN
MjkwMTA4MTgwMDU5WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXPiZOUnr
0PCHPU2Ow5iWF/o3j62UdpAyR5Oj+MFCyUDUdUc/i3JZDhIC+bY1PCheIAHCmnl2
lDIfM5HO8yoJLKM4MDYwDgYDVR0PAQH/BAQDAgKkMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgPKz19+N/YJ4b
77KaccUO9dzHopktAfTmRwMF1EjpaecCIBm9Bo/1QJtHjVcWA7FhjlmZ2ZeNai0S
WH+LmZunWa9R
-----END CERTIFICATE-----
`

const snakeKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIC6S8jxVI0Kvu3GWqp3Tj3Yeq0Ifit80ftljLeB/Ia0qoAoGCCqGSM49
AwEHoUQDQgAEXPiZOUnr0PCHPU2Ow5iWF/o3j62UdpAyR5Oj+MFCyUDUdUc/i3JZ
DhIC+bY1PCheIAHCmnl2lDIfM5HO8yoJLA==
-----END EC PRIVATE KEY-----
`

func InitTLS() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		cert, err = tls.X509KeyPair([]byte(snakeCert), []byte(snakeKey))
		if err != nil {
			panic("Failed to load cert.pem & key.pem")
		}
	}
	SnakeTLS = &tls.Config{Certificates: []tls.Certificate{cert}}
}

type SavedTCPFrame struct {
	net.Conn
	frame *bytes.Reader
}

func (conn *SavedTCPFrame) Read(b []byte) (n int, err error) {
	if conn.frame != nil && conn.frame.Len() > 0 {
		return conn.frame.Read(b)
	}
	conn.frame = nil
	return conn.Conn.Read(b)
}

// Wrap TCP connection into a TLS one. Allows one to specify 'frame', buffer with client hello we've
// already consumed from the TCP socket. This one will be injected into our own TLS state.
func TLSUpgrade(conn net.Conn, config *tls.Config, hello []byte) (tc *tls.Conn) {
	if hello != nil {
		conn = &SavedTCPFrame{
			Conn:conn,
			frame:bytes.NewReader(hello),
		}
	}
	return tls.Server(conn, config)
}

