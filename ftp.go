package onion2web

import (
	"bufio"
	"net"
	"strings"
	"time"
)

func FTPHandle(conn net.Conn, dport int) {
	var peer net.Conn
	defer func() {
		conn.Close()
		if peer != nil {
			peer.Close()
		}
	}()
	conn.Write([]byte("220 onion2web.com FTP proxy. AUTH TLS mandatory." ))
	reader := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(ReadTimeout * time.Second))
		ln, _, readerr := reader.ReadLine()
		if readerr != nil {
			return
		}
		cmd := strings.ToUpper(string(ln))
		if cmd == "QUIT" {
			conn.Write([]byte("221 Bye\r\n" ))
			return
		}
		if cmd != "AUTH TLS" {
			conn.Write([]byte("500 Need AUTH TLS first.\r\n" ))
		}
		conn.Write([]byte(cmd + " successful\r\n"))
		frame, sni := SNIParse(conn)
		if frame == nil {
			return
		}
		if sni == "" {
			conn = TLSUpgrade(conn, SnakeTLS, frame)
			conn.Write([]byte("550 Your FTP client is out of date. This server supports only AUTH TLS with SNI."))
			return
		}
		target := OnionResolve(sni)
		if target != nil {
			peer = TorDial(target, 21)
			if peer != nil {
				preader := bufio.NewReader(peer)
				// skip banner
				for {
					peer.SetReadDeadline(time.Now().Add(ReadTimeout * time.Second))
					ln, _, err := preader.ReadLine()
					if err != nil {
						return
					}
					if len(ln) < 4 {
						return
					}
					if ln[3] == ' ' {
						break
					}
					_, err = peer.Write(frame)
					if err != nil {
						return
					}
					IOPump(conn, peer)
				}
			}
		}
	}
}
