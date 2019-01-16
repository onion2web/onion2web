// TODO:  L7 brings insanity. Clean this mess.

package onion2web

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/toorop/go-dkim"
	"log"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

const SMTPHostName = "mail.onion2web.com"
const AllowRelay = true
const MandatoryTls = false
const MaxBodySize = 1024 * 1024

func SMTPHandle(conn net.Conn, dport int) {
	log.Println("INCOMING")
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
		var toolong bool
		conn.SetReadDeadline(time.Now().Add(ReadTimeout * time.Second))
		ln, toolong, readerr = reader.ReadLine()
		if toolong || readerr != nil {
			return nil
		}
		return
	}
	hfrom := "unknown"
	hastls := false
	mfrom := ""
	sni := ""
	args := ""
	relaying := false
	var dmxlist []*net.MX
	var frame []byte
	var mfa *mail.Address
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
		case "DATA": {
			if !relaying {
				send(503, "Need RCPT TO")
				continue
			}
			relaying = false
			if (MandatoryTls && !hastls) {
				break
			}
			send(352,"Go ahead. End your data with <CR><LF>.<CR><LF>")
			var body []byte
			for {
				ln := recv()
				if len(ln) > 1000 {
					return
				}
				if ln == nil {
					return
				}
				if len(ln) == 1 && ln[0] == '.' {
					break
				}
				body = append(body, ln...)
				if len(body) > MaxBodySize {
					send(552,"Message size exceeded.")
					return
				}
			}

			var mxcli *smtp.Client
			var mxpeer net.Conn
			//find working mx
			var rmx *net.MX
			for _, rmx = range dmxlist {
				var err error
				mxcli = nil
				mxpeer, err = net.DialTimeout("tcp", rmx.Host + ":25", 5 * time.Second)
				if err != nil {
					continue
				}
				mxcli, err = smtp.NewClient(mxpeer, "smtp.onion2web.com")
				if err == nil {
					break
				}
				mxpeer.Close()
			}

			if mxcli == nil {
				send(554, "Relay failed; no useable MX found")
				continue
			}

			mxpeer.SetDeadline(time.Now().Add(ReadTimeout * time.Second))
			if mxcli.StartTLS(&tls.Config{ServerName:rmx.Host}) != nil {
				send(554, "Relay failed; " + rmx.Host + " TLS error")
				mxcli.Close()
				continue

			}
			msg, err := mail.ReadMessage(bytes.NewReader(body))
			if err != nil {
				send(554, "Relay failed; failed to parse message")
				mxcli.Close()
				continue
			}
			ct := msg.Header.Get("Content-Type")
			mtype, _, err := mime.ParseMediaType(ct)
			if err != nil || mtype != "text/plain" {
				send(554, "This relay accepts only text/plain email, with no attachments.")
				mxcli.Close()
				continue
			}

			wdat, err := mxcli.Data()
			if err != nil {
				send(554, err.Error())
				mxcli.Close()
				continue
			}

			dkver, _ := dkim.Verify(&body)
			if dkver != dkim.SUCCESS {
				send(554, "DKIM verification failed.")
				mxcli.Close()
				continue
			}

			_, err = wdat.Write(body)
			if err != nil || wdat.Close() != nil {
				send(554, err.Error())
				mxcli.Close()
				continue
			}
			mxcli.Quit()
			send(250, "Ok; relayed to " + rmx.Host)
			continue
		}
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
			if hastls {
				return
			}
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
			if (!strings.HasPrefix(strings.ToUpper(string(ln)), "MAIL FROM:")) {
				send(501, "Malformed MAIL FROM:, got '"+mfrom+"'")
				continue
			}
			var err error
			mfa, err = mail.ParseAddress(string(args[5:]))
			if err != nil {
				send(501, err.Error())
				continue
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
			dmxlist, err = net.LookupMX(strings.Split(pa.Address, "@")[1])
			if err != nil {
				send(510, "DNS error "+ err.Error())
				continue
			}
			if len(dmxlist) == 0 {
				send(510, "No MX found for the address.")
				continue
			}
			hasOnions := false
			for _, v := range dmxlist {
				onion := OnionResolve(v.Host)
				if onion != nil {
					hasOnions = true
				}
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
			if hasOnions || !AllowRelay {
				send(451, "Failed to contact target MX for this address (HidServ is down)")
				continue
			}
			// This is a relay request.
			if !canRelay(mfa.Address) {
				send(454, "Relay access denied")
				continue
			}
			send(250, "Ok")
			relaying = true
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

func canRelay(addr string) (ok bool) {
	mxlist, err := net.LookupMX(strings.Split(addr, "@")[1])
	if err != nil {
		return
	}
	for _, v := range mxlist {
		if (!strings.HasSuffix(v.Host, ".onion2web.com.")) {
			return
		}
	}
	return true
}