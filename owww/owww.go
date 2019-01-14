package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"gopkg.in/irc.v3"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"onion2web"
	"strings"
	"time"
)

func main() {
	onion2web.InitTLS()
	onion2web.InitResolver()

	speed := flag.Int("speed", 20, "Relay speed in mbit/s, your Tor instance must handle as much")
	contact := flag.String("contact", "", "Contact information (email or IRC nick)")
	bindip := flag.String("bindip", "0.0.0.0", "IP address to bind ports on")
	extip := flag.String("extip", "auto", "External IP the ports are accessible on (far NAT)")
	offset := flag.Int("offset", 0, "Offset bound port numbers (for NAT)")
	silent := flag.Bool("silent", false, "Don't log to stdout")
	socks := flag.String("socks", "127.0.0.1:9050", "Tor client socks host:port, 127.0.0.1:9150 for Tor browser")
	flag.Parse()

	if *silent {
		log.SetOutput(ioutil.Discard)
	}

	parsedip, err := net.ResolveIPAddr("ip4", *bindip)
	if err != nil {
		panic(err)
	}

	var extparsed *net.IPAddr
	if *extip != "auto" {
		extparsed, err = net.ResolveIPAddr("ip4", *extip)
	}

	onion2web.TorSocksAddr = "socks5://" + *socks
	_, err = url.Parse(onion2web.TorSocksAddr)
	if err != nil {
		panic(err)
	}
	log.Printf("Using Tor instance at %s\n", onion2web.TorSocksAddr)

	bind := func(port, dport int, cb func (client net.Conn, dport int)) {
		port += *offset
		log.Printf("Bound %s:%d -> <HS>:%d\n", *bindip, port, dport)
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *bindip, port))
		if err != nil {
			panic(err)
		}
		go func() {
			for {
				fd, err := listener.Accept()
				if err == nil {
					go cb(fd, dport)
				} else {
					time.Sleep(1 * time.Second)
				}
			}
		}()
	}

	// ALG proxies
	bind(21, 21, onion2web.FTPHandle)
	bind(25, 25, onion2web.SMTPHandle)
	bind(80, 80, func(fd net.Conn, dport int) {
		badgw := "HTTP/1.0 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\n"
		onion2web.HTTPHandle(fd,
			badgw+"Cannot parse target Host:, or DNS CNAME for it's .onion not configured properly\n",
			badgw+"Hidden Service is down\n")
	})

	// Common internet services with straight TLS session
	bind(443, 443, onion2web.SNIHandle)
	bind(465, 465, onion2web.SNIHandle)
	bind(563, 563, onion2web.SNIHandle)
	bind(636, 636, onion2web.SNIHandle)
	bind(853, 853, onion2web.SNIHandle)
	bind(989, 989, onion2web.SNIHandle)
	bind(990, 990, onion2web.SNIHandle)
	bind(992, 992, onion2web.SNIHandle)
	bind(993, 993, onion2web.SNIHandle)
	bind(994, 994, onion2web.SNIHandle)
	bind(995, 995, onion2web.SNIHandle)
	bind(5061, 5061, onion2web.SNIHandle)
	bind(5223, 5223, onion2web.SNIHandle)
	bind(5269, 5269, onion2web.SNIHandle)
	bind(6697, 6697, onion2web.SNIHandle)
	bind(7000, 7000, onion2web.SNIHandle)
	bind(8443, 8443, onion2web.SNIHandle)

	// Just heads up, not a proxy.
	bind(6667, 0, func(fd net.Conn, dport int) {
		fd.SetWriteDeadline(time.Now().Add(onion2web.WriteTimeout * time.Second))
		fd.Write([]byte("ERROR :This IRC server is SSL only (ports 6697 or 7000, irssi>=0.8.18)\r\n"))
		time.Sleep(100 * time.Millisecond)
		fd.Close()
	})

	// Just sit and idle on IRC, and the tracker script will eventually discover us and publish in *.onion2web.com zone.
	// The tracker can also pass a message if it detects something misconfigured.
	backoff := 5
	log.Println("Connecting to the tracker...")
	for {
		d := net.Dialer{LocalAddr:&net.TCPAddr{parsedip.IP, 0, ""}, Timeout:5 * time.Second}
		conn, err := d.Dial("tcp4", "tracker.onion2web.com:7000")
		if err == nil {
			conn = tls.Client(conn, &tls.Config{
				InsecureSkipVerify: true,
			})
		}
		if err != nil {
			log.Println(err)
			backoff *= 2
			time.Sleep(time.Duration(backoff) * time.Second)
			continue
		}
		backoff = 5
		extip2 := conn.LocalAddr().(*net.TCPAddr).IP

		if extparsed != nil {
			extip2 = extparsed.IP
		}
		ipbytes := extip2.To4()
		auth := map[string]bool{}
		iphex := fmt.Sprintf("%02X%02X%02X%02X", ipbytes[0], ipbytes[1], ipbytes[2], ipbytes[3])
		config := irc.ClientConfig{
			Nick: "ow" + iphex,
			User: "o2www",
			Name: fmt.Sprintf("v%d %d %s %s", onion2web.Version, *speed, extip2.String(), *contact),
			Handler: irc.HandlerFunc(func(c *irc.Client, m *irc.Message) {
				if m.Command == "001" {
					c.Write("MODE " + c.CurrentNick() + " -h")
					go func() {
						for {
							if c.Write("JOIN #onion2web") != nil {
								return
							}
							time.Sleep(300 * time.Second)
						}
					}()
				}
				if m.Command == "366" {
					log.Printf("Connected. Proxy %s is now submitted to the tracker.\n", extip2.String())
				}
				if m.Command == "PRIVMSG" && !c.FromChannel(m) && auth[m.Name] {
					log.Println(m.Trailing())
				}
				if m.Command == "353" {
					for _, n := range strings.Fields(m.Trailing()) {
						if strings.HasPrefix(n, "@") || strings.HasPrefix(n,"+") {
							auth[n[1:]] = true
						}
					}
				}
			}),
		}
		cli := irc.NewClient(conn, config)
		err = cli.Run()
		log.Println(err)
		time.Sleep(30 * time.Second)
	}
}


