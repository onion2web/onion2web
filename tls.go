// TLS utilities
package onion2web

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log"
	"math/big"
	"net"
	"time"
)

// Used only in certain edge cases, currently for opportunistic SMTP STARTLS.
// Such sessions are MITMable regardless, but at least we can hide from passive onlookers.
var SnakeTLS *tls.Config

func InitTLS() {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	log.Println("Generating snake oil certificate for opportunistic TLS")
	template := x509.Certificate {
		SerialNumber: big.NewInt(0),
		NotBefore: time.Now(),
		NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	cert := tls.Certificate{
		Certificate:[][]byte{der},
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

