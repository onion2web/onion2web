// Handles access to onion peers
package onion2web

import (
	"io"
	"log"
	"math/rand"
	"net"
	"time"
)
var TorSocksAddr = "127.0.0.1:9050"

func TorDial(onions []string, port int) (conn net.Conn) {
	if onions == nil {
		return
	}
	for _, i := range rand.Perm(len(onions)) {
		conn = TorDialOne(onions[i], port)
		// found a working one
		if conn != nil {
			break
		}
	}
	return
}

func TorDialOne(onion string, port int) net.Conn {
	conn, err := net.Dial("tcp", TorSocksAddr)
	if err != nil {
		log.Println(err)
		return nil
	}
	conn.SetWriteDeadline(time.Now().Add(SocksDialTimeout * time.Second))

	_, err = conn.Write(append(append(
		[]byte{0x04, 0x01, byte(port>>8), byte(port), 0,0,0,1, 0},
		[]byte(onion)...
	), 0))

	// terminates onion.
	conn.SetReadDeadline(time.Now().Add(ReadTimeout * time.Second))
	var buf [2]byte
	_, err = io.ReadFull(conn, buf[:])
	if err != nil {
		conn.Close()
		return nil
	}
	if buf[0] != 0 || buf[1] != 0x5a {
		conn.Close()
		return nil
	}
	var dummy [6]byte
	_, err = io.ReadFull(conn, dummy[:])
	if err != nil {
		conn.Close()
		return nil
	}
	return conn
}