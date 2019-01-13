package onion2web

import (
	"net"
	"time"
)

var IoPool = MakeBufPool(20, 4096)

// When a read or write fails, we exit.
func IOCopy(input net.Conn, output net.Conn) {
	buf := IoPool.Get()
	to := time.Duration(ReadTimeout)
	for {
		input.SetReadDeadline(time.Now().Add(to * time.Second))
		count, err := input.Read(buf)
		to = time.Duration(LongReadTimeout)
		if count > 0 {
			output.SetWriteDeadline(time.Now().Add(WriteTimeout * time.Second))
			_, err2 := output.Write(buf[:count])
			if err2 != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	IoPool.Put(buf)
}

func IOPump(input,output net.Conn) {
	go func() {
		defer func() {
			output.Close()
			input.Close()
		}()
		IOCopy(output, input)
	}()
	IOCopy(input, output)
	input.Close()
	output.Close()
}

