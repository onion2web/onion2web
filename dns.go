// Resolves domains to .onion backend by pulling mappings from DNS
package onion2web

import (
	"log"
	"net"
	"strings"
)

func InitResolver() {
	net.DefaultResolver.PreferGo = true
}

func GetOnion(rec string) string {
	parts := strings.SplitN(rec, ".", 2)
	if len(parts[0]) == 16 || len(parts[0]) == 56 {
		return parts[0]
	}
	return ""
}


// First, pick up CNAME or TXT fallback. Returns nil if no mapping exists.
func OnionResolve(domain string) (onions []string) {
	log.Println("Resolving " + domain)
	cn, err := net.LookupCNAME(domain)
	if err == nil {
		println(cn)
		on := GetOnion(cn)
		if on != "" {
			return []string{on + ".onion"}
		}
	}
	cns, err := net.LookupTXT(domain)
	if err == nil {
		for _, cn := range cns {
			on := GetOnion(cn)
			if on != "" {
				println(cn)
				onions = append(onions, on + ".onion")
			}
		}
	}
	return
}

