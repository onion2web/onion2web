// Handles generic proxying of TLS services via SNI routing
package onion2web

import (
	"io"
	"net"
	"time"
)

const SNIWait = 30			// Waiting for initial packet bytes
const SNIWait2 = 15			// Waiting for rest of the hello packet
const ReadTimeout = 60		// Waiting for incoming bytes on a socket
const LongReadTimeout = 700	// Allow long pauses after initial read on during pipe
const WriteTimeout = 15		// For how long a single Write() can block
const SocksDialTimeout = 30

// Pass a TCP socket with incoming TLS session. Returns the consumed buffer (to be replayed at proxy endpoint)
// and SNI name gleaned from the hello (or empty string if no SNI). If the stream is not valid TLS, ret=nil
func SNIParse(conn net.Conn) (ret []byte, sni string) {
	ret = nil
	sni = ""
	var rec [5]byte
	conn.SetReadDeadline(time.Now().Add(SNIWait * time.Second))
	got, err := io.ReadFull(conn, rec[:])
	if err != nil || got != 5 {
		return
	}
	// must be recordTypeHandshake=22
	if rec[0] != 22 {
		return
	}
	n := (int(rec[3]) << 8) | int(rec[4])
	frame := make([]byte, 5 + n)
	p := frame[5:]
	copy(frame, rec[:])
	conn.SetReadDeadline(time.Now().Add(SNIWait2 * time.Second))
	got, err = io.ReadFull(conn, p)
	if err != nil || got != len(p) {
		return
	}
	n = int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	// Must be typeClientHello=1, and we must have the message in its entirety (we dont allow fragging)
	if p[0] != 1 || n < 42 || n > (len(p)-4) {
		return
	}

	// skip sessionid
	sidlen := int(p[38])
	if sidlen > 32 || len(p) < 39+sidlen {
		return
	}
	p = p[39+sidlen:]

	// skip cipher suite list
	if len(p) < 2 {
		return
	}
	cslen := int(p[0])<<8 | int(p[1])
	if cslen&1 == 1 || len(p) < 2+cslen {
		return
	}
	p = p[2+cslen:]

	// skip comp methods
	cmlen := int(p[0])
	if len(p) < 1+cmlen {
		return
	}

	// now look at extensions
	p = p[1+cmlen:]
	if len (p) == 1 {
		return
	}

	// the handshake seems valid, but no sni present
	if len (p) < 2 {
		return frame, ""
	}
	exlen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if exlen != len(p) {
		return
	}
	for len(p) != 0 {
		if len(p) < 4 {
			return
		}
		exid := uint16(p[0])<<8 | uint16(p[1])
		dlen := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < dlen {
			return
		}
		// must be SNI
		if exid == 0 {
			// now parse SNI record
			snirec := p[0:dlen]
			if len(snirec) < 2 {
				return
			}
			nmlen := int(snirec[0])<<8 | int(snirec[1])
			snirec = snirec[2:]
			if len(snirec) != nmlen {
				return
			}
			for len(snirec) > 0 {
				if len(snirec) < 3 {
					return
				}
				ntyp := snirec[0]
				nlen := int(snirec[1])<<8 | int(snirec[2])
				snirec := snirec[3:]
				if len(snirec) < nlen {
					return
				}
				if ntyp == 0 {
					//println("got sni")
					return frame, string(snirec[:nlen])
				}
				snirec = snirec[:nlen]
			}
		}
		p = p[dlen:]
	}
	return frame, ""
}

// Generic SNI handler 	(for IRC and HTTPS).
// - parse SNI from stream
// - if SNI is not present, establish our own TLS session and print out errstr, close & return
// - if SNI is present, invoke Tor dialer (which does all the resolving). If no suitable onion is found, errstr again
// - if the dial succeeds, run a 2-way pipe
func SNIHandle(conn net.Conn, port int, errstr string, isdown string) {
	defer conn.Close()
	frame, sni := SNIParse(conn)
	if frame == nil {
		return
	}
	conn.SetWriteDeadline(time.Now().Add(WriteTimeout * time.Second))
	target := OnionResolve(sni)
	if target == nil {
		tc := TLSUpgrade(conn, SnakeTLS, frame)
		if errstr != "" {
			tc.Write([]byte(errstr))
		}
		tc.CloseWrite()
		var b [1]byte
		tc.Read(b[:])
		time.Sleep(100 * time.Millisecond)
		conn = tc
		return
	}
	peer := TorDial(target, port)
	if peer == nil {
		tc := TLSUpgrade(conn, SnakeTLS, frame)
		if isdown != "" {
			tc.Write([]byte(isdown))
		}
		tc.CloseWrite()
		var b [1]byte
		tc.Read(b[:])
		time.Sleep(100 * time.Millisecond)
		conn = tc
		return
	} else {
		peer.Write(frame)
	}
	IOPump(conn, peer)
	// conn.Close early defer
}

