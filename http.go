// Handles proxying of plain HTTP (by inspecting Host:)
package onion2web

import (
	"bytes"
	"net"
	"strings"
	"time"
)

const HttpBufSize = 16384
var hostHdr = []byte("\nHost: ")
var badgw = "HTTP/1.0 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\n"
var HttpBufPool = MakeBufPool(5, HttpBufSize)

// Snatch Host: and route to onion according to it. High level http/line buffered processing is not used,
// so as to avoid GC pressure. Same reason why the single buffer we do use is pooled.
func HTTPHandle(conn net.Conn, errstr string, isdown string) {
	mem := HttpBufPool.Get()
	defer conn.Close()
	defer HttpBufPool.Put(mem)
	pos := 0
	for pos < HttpBufSize {
		conn.SetWriteDeadline(time.Now().Add(WriteTimeout * time.Second))
		for i := 1; i < pos - 2; i++ {
			p := mem[i:]
			if bytes.HasPrefix(p, hostHdr) {
				hend := bytes.IndexByte(p, '\r')
				if hend == -1 {
					break
				}
				host := string(p[7:hend])
				target := OnionResolve(strings.SplitN(host, ":",2)[0])
				if target == nil {
					conn.Write([]byte(errstr))
					return
				}
				peer := TorDial(target, 80)
				if peer == nil {
					conn.Write([]byte(isdown))
					return
				}

				// Pass up the request we ate previously
				_, err := peer.Write(mem[:pos])
				if err != nil {
					return
				}

				// Free up the http buffer
				HttpBufPool.Put(mem)
				mem = nil // cancels defer

				// And now pipe
				IOPump(conn, peer)
				return
			}
			if p[0] == '\n' && p[1] == '\r' {
				conn.Write([]byte(errstr))
				return
			}
		}
		conn.SetReadDeadline(time.Now().Add(ReadTimeout * time.Second))
		got, err := conn.Read(mem[pos:])
		if err != nil {
			return
		}
		pos += got
	}
}

