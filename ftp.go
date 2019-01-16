package onion2web

import (
	"bufio"
	"log"
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
	conn.Write([]byte("220 onion2web.com FTP proxy. AUTH TLS mandatory.\r\n" ))
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
		conn.Write([]byte("234 AUTH TLS ok\r\n"))
		frame, sni := SNIParse(conn)
		if frame == nil {
			return
		}
		log.Println(sni)
		//sni = "www.onion2web.com"
		if sni == "" {
			conn = TLSUpgrade(conn, SnakeTLS, frame)
			conn.Write([]byte("550 Your FTP client is out of date. This server supports only AUTH TLS with SNI.\r\n"))
			return
		}
		target := OnionResolve(sni)
		log.Println(target)
		if target != nil {
			peer = TorDial(target, 21)
			log.Print("dialed")
			if peer != nil {
				preader := bufio.NewReader(peer)
				// skip banner
				peer.SetReadDeadline(time.Now().Add(ReadTimeout * time.Second))
				for {
					ln, _, err := preader.ReadLine()
					log.Println(string(ln))
					if err != nil {
						return
					}
					if len(ln) < 4 {
						return
					}
					if ln[3] == ' ' {
						break
					}
				}
				peer.Write([]byte("AUTH TLS\r\n"))
				_, _, err := preader.ReadLine()
				_, err = peer.Write(frame)
				if err != nil {
					return
				}
				IOPump(conn, peer)
			}
		}
	}
}
