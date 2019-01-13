package onion2web

import (
	"bufio"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"
)

const SMTPHostName = "mail.onion2web.com"
const MandatoryTls = false

func SMTPHandle(conn net.Conn) {
	var peer net.Conn
	defer func() {
		conn.Close()
		if peer != nil {
			peer.Close()
		}
	}()
	send := func(code int, line ...string) (ret bool) {
		conn.SetWriteDeadline(time.Now().Add(WriteTimeout * time.Second))
		i := 0; for ;i < len(line)-1; i++ {
			msg := fmt.Sprintf("%d-%s\r\n", code, line[i])
			//print("US>SMX: " + msg)
			_, err := conn.Write([]byte(msg))
			if err != nil {
				return
			}
		}
		msg := fmt.Sprintf("%d %s\r\n", code, line[i])
		//print("US>SMX: " + msg)
		_, err := conn.Write([]byte(msg))
		if err != nil {
			return
		}
		return true
	}

	sendcheck := func(peer net.Conn, line ...string) (ok bool) {
		pread := bufio.NewReader(peer)
		var err error
		for _, v := range line {
			conn.SetWriteDeadline(time.Now().Add(WriteTimeout * time.Second))
			if v != "" {
				//println("US>RMX: " + v)
				_, err = peer.Write([]byte(v + "\r\n"))
				if err != nil {
					return
				}
			}
			var pln []byte
			for {
				peer.SetReadDeadline(time.Now().Add(ReadTimeout * time.Second))
				pln, _, err = pread.ReadLine()
				//println("RMX>US: " + string(pln))
				if err != nil {
					return
				}
				// malformed or error
				if len(pln) < 4 || pln[0] >= '4' {
					return
				}
				// last one, done
				if pln[3] == ' ' {
					break
				}
			}
		}
		return true
	}

	if MandatoryTls {
		send(220, SMTPHostName+" ESMTP proxy (STARTTLS mandatory)")
	} else {
		send(220, SMTPHostName+" ESMTP proxy")
	}
	reader := bufio.NewReader(conn)
	var readerr error
	recv := func() (ln []byte) {
		conn.SetReadDeadline(time.Now().Add(ReadTimeout * time.Second))
		ln, _, readerr = reader.ReadLine()
		return
	}
	hfrom := "unknown"
	hastls := false
	mfrom := ""
	sni := ""
	args := ""
	var frame []byte
	for {
		ln := recv()
		//println("RMX>US: " + string(ln))
		if readerr != nil {
			//print(readerr)
			return
		}
		parts := strings.SplitN(string(ln), " ", 2)
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToUpper(parts[0])
		if len(parts) > 1 {
			args = parts[1]
		}
		switch cmd {
		case "HELO": {
			send(250, SMTPHostName)
			hfrom = string(parts[1])
			continue
		}
		case "EHLO": {
			send(250, SMTPHostName, "STARTTLS")
			hfrom = string(parts[1])
			continue
		}
		case "QUIT": {
			send(221, "Bye.")
			return
		}
		case "STARTTLS": {
			send(220, "Ready to start TLS")
			frame, sni = SNIParse(conn)
			if frame == nil {
				return
			}
			// SNI works and end-to-end passthru as well
			if sni != "" {
				target := OnionResolve(sni)
				if target != nil {
					peer = TorDial(target, 25)
					if peer != nil {
						// fast-forward to starttls phase
						if sendcheck(peer, "", "EHLO " + hfrom, "STARTTLS") {
							peer.SetWriteDeadline(time.Now().Add(WriteTimeout * time.Second))
							_, err := peer.Write(frame)
							//println("start pump", err)
							if err == nil {
								IOPump(conn, peer)
							}
						}
						return
					}
				}
			}

			conn = TLSUpgrade(conn, SnakeTLS, frame)
			reader = bufio.NewReader(conn)
			hastls = true
			continue
		}
		case "MAIL": {
			if (MandatoryTls && !hastls) {
				break
			}
			mfrom = string(ln)
			send(250, "ok")
			continue
		}
		case "RCPT": {
			if (MandatoryTls && !hastls) || len(cmd) < 2 || len(args) < 3 {
				break
			}
			if mfrom == "" {
				send(503, "Need MAIL FROM: first")
				continue
			}
			pa, err := mail.ParseAddress(string(args[3:]))
			if err != nil {
				send(501, err.Error())
				continue
			}
			if !strings.Contains(pa.Address, "@") {
				send(510, "Malformed address")
				continue
			}
			mxlist, err := net.LookupMX(strings.Split(pa.Address, "@")[1])
			if err != nil {
				send(510, "DNS error "+ err.Error())
				continue
			}
			if len(mxlist) == 0 {
				send(510, "No MX found for the address.")
				continue
			}
			for _, v := range mxlist {
				onion := OnionResolve(v.Host)
				peer = TorDial(onion, 25)
				if peer != nil {
					// Spams:
					// >> HELO (original helo)
					// 220
					// MAIL FROM: (original mfrom)
					// 250
					// RCPT TO: (original rcpt to)
					// 250
					// skips over all responses until we see 250 in response to rcpt-to
					if sendcheck(peer, "", "EHLO " + hfrom, mfrom) {
						_, err := peer.Write(append(ln,13,10))
						if err == nil {
							//println("start pump", err)
							IOPump(conn, peer)
							return
						}
					}
					peer.Close()
					peer = nil
				}
				continue
			}
			send(451, "Failed to contact target MX for this address (HidServ is down)")
			continue
		}
		default: {
			send(502, "Command not implemented")
			continue
		}
		}
		send(530, "Must issue STARTTLS command first.")
	}
}
