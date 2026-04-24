package trusted

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
)

var (
	mu    sync.RWMutex
	nets  []*net.IPNet
	paths = []string{
		"global/trusted/cloudflare_ipv4.txt",
		"global/trusted/cloudflare_ipv6.txt",
		"global/trusted/extra.txt",
	}
)

func Load() error {
	parsed := make([]*net.IPNet, 0, 32)
	for _, p := range paths {
		file, err := os.Open(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !strings.Contains(line, "/") {
				if strings.Contains(line, ":") {
					line += "/128"
				} else {
					line += "/32"
				}
			}
			_, cidr, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
			parsed = append(parsed, cidr)
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return err
		}
		file.Close()
	}

	mu.Lock()
	nets = parsed
	mu.Unlock()
	return nil
}

// IsTrusted reports whether the given address string (host or host:port) falls
// inside any configured trusted CIDR. Both bare IPs and IPv4/IPv6 host:port
// forms are accepted; net.SplitHostPort handles the bracketed IPv6 case.
func IsTrusted(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	mu.RLock()
	defer mu.RUnlock()
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
