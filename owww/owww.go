package main

import (
	"net"
	"onion2web"
	"time"
)

func main() {
	onion2web.InitTLS()
	onion2web.InitResolver()

	httpSock, err := net.Listen("tcp", "0.0.0.0:80")
	if err != nil {
		panic(err)
	}
	ircsSock, err := net.Listen("tcp", "0.0.0.0:6697")
	if err != nil {
		panic(err)
	}
	ircSock, err := net.Listen("tcp", "0.0.0.0:6667")
	if err != nil {
		panic(err)
	}
	httpsSock, err := net.Listen("tcp", "0.0.0.0:443")
	if err != nil {
		panic(err)
	}
	smtpSock, err := net.Listen("tcp", "0.0.0.0:25")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			fd, err := smtpSock.Accept()
			if err != nil {continue}
			go onion2web.SMTPHandle(fd)
		}
	}()
	var badgw = "HTTP/1.0 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\n"
	go func() {
		for {
			fd, err := httpsSock.Accept()
			if err != nil {continue}
			go onion2web.SNIHandle(fd, 443, badgw+"SNI missing, or CNAME to .onion is not configured properly\n", badgw+"Hidden Service is down\n")
		}
	}()
	go func() {
		for {
			fd, err := httpSock.Accept()
			if err != nil {
				continue
			}
			go onion2web.HTTPHandle(fd, badgw+"Host: header missing or malformed, or CNAME not configured properly\n", badgw+"Hidden Service is down\n")
		}
	}()
	notice := "ERROR :"
	go func() {
		for {
			fd, err := ircsSock.Accept()
			if err != nil {continue}

			go func () {
				onion2web.SNIHandle(fd, 7000,
					notice+"Misconfigured DNS, or your IRC client doesn't support SNI (needs irssi>=0.8.18)\r\n",
					notice+"Hidden Service is down\r\n")
			}()
		}
	}()
	go func() {
		for {
			fd, err := ircSock.Accept()
			if err != nil {
				continue
			}
			fd.SetWriteDeadline(time.Now().Add(onion2web.WriteTimeout * time.Second))
			fd.Write([]byte(notice + "IRC server for this domain is reachable only through SSL ports 6697 (irssi>=0.8.18 for SNI)\r\n\r\n"))
			time.Sleep(100 * time.Millisecond)
			fd.Write([]byte("\r\n"))
			fd.Close()
		}
	}()
	/*for {
		fd, _ := stest.Accept()
		frame, sni := onion2web.SNIParse(fd)
		println(sni)
		fd2 := onion2web.TLSUpgrade(fd, onion2web.SnakeTLS, frame)
		fd2.Write([]byte("Hello!\n"))
		fd2.Close()
	}*/
	select {}
}
