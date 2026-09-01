package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/proxy"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	PrintMutex   = &sync.Mutex{}
	ColorsString = "0;31"
)

// Only run in locked thread
func AddLogs(entry domains.DomainLog, domainName string) {
	domainData := domains.DomainsData[domainName]
	domainData.LastLogs = append(domainData.LastLogs, entry)
	domains.DomainsData[domainName] = domainData
}

func FormatLogs(log domains.DomainLog) string {
	if log.BrowserFP != "" || log.BotFP != "" {
		return "[ " + PrimaryColor(log.Time) + " ] > \033[35m" + log.IP + "\033[0m - \033[32m" + log.BrowserFP + log.BotFP + "\033[0m - " + PrimaryColor(log.Useragent) + " - " + PrimaryColor(log.Path)
	}
	return "[ " + PrimaryColor(log.Time) + " ] > \033[35m" + log.IP + "\033[0m - \033[31mUNK (" + log.TLSFP + ")\033[0m - " + PrimaryColor(log.Useragent) + " - " + PrimaryColor(log.Path)
}

// Only run in locked thread
func ReadLogs(domainName string) {
	// WAVE 9 (CONC-07): snapshot and trim under one write lock. The old
	// RLock'd copy decided the trim after releasing it, so entries AddLogs
	// appended in between were lost when the stale copy-back overwrote the
	// map's newer slice header. The locked section is one map read plus an
	// occasional re-slice; the terminal I/O loop below stays outside it.
	firewall.Mutex.Lock()
	domainData := domains.DomainsData[domainName]

	//Calculate how close we are to overflowing
	logOverflow := len(domainData.LastLogs) - proxy.MaxLogLength

	if logOverflow > 0 {
		// Remove overflown element(s)
		domainData.LastLogs = domainData.LastLogs[logOverflow:]
		domains.DomainsData[domainName] = domainData
	}
	firewall.Mutex.Unlock()

	for i, log := range domainData.LastLogs {
		// Check if out log is too big to display fully

		parsedOut := FormatLogs(log)

		if len(parsedOut)+4 > proxy.TWidth {
			fmt.Print("\033[" + fmt.Sprint(11+i) + ";1H\033[K[" + PrimaryColor("-") + "] " + parsedOut[:len(parsedOut)-(len(parsedOut)+4-proxy.TWidth)] + " ...\033[0m\n")
		} else {
			fmt.Print("\033[" + fmt.Sprint(11+i) + ";1H\033[K[" + PrimaryColor("-") + "] " + parsedOut + "\n")
		}
	}
	MoveInputLine()
}

// Only run in locked thread
func ClearLogs(domainName string) domains.DomainData {
	domainData := domains.DomainsData[domainName]
	domainData.LastLogs = nil
	domains.DomainsData[domainName] = domainData
	return domainData
}

func MoveInputLine() {
	fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + PrimaryColor("Command") + " ]: \033[u\033[s")
}

func PrimaryColor(input string) string {
	return "\033[" + ColorsString + "m" + input + "\033[0m"
}

func SetColor(colorMap []string) {
	ColorsString = strings.Join(colorMap, ";")
}

func ClearScreen(length int) {
	fmt.Print("\033[s")
	for j := 1; j < 9+length; j++ {
		fmt.Println("\033[" + fmt.Sprint(j) + ";1H\033[K")
	}
}

func ReadTerminal() string {
	reader := bufio.NewScanner(os.Stdin)
	reader.Scan()
	return strings.ToLower(reader.Text())
}

func EvalYN(input string, defVal bool) (result bool) {
	switch input {
	case "y":
		return true
	case "yes":
		return true
	case "true":
		return true
	case "n":
		return false
	case "no":
		return false
	case "false":
		return false
	default:
		return defVal
	}
}

func AskBool(question string, defaultVal bool) bool {
	fmt.Print("[" + PrimaryColor("+") + "] [ " + PrimaryColor(question) + " ]: ")
	input := ReadTerminal()
	if input == "" {
		fmt.Println("[" + PrimaryColor("-") + "] [ " + PrimaryColor("Using Default Value "+fmt.Sprint(defaultVal)) + " ]")
		return defaultVal
	}
	return EvalYN(input, defaultVal)
}

func AskInt(question string, defaultVal int) int {
	fmt.Print("[" + PrimaryColor("+") + "] [ " + PrimaryColor(question) + " ]: ")
	input := ReadTerminal()
	if input == "" {
		fmt.Println("[" + PrimaryColor("-") + "] [ " + PrimaryColor("Using Default Value "+fmt.Sprint(defaultVal)) + " ]")
		return defaultVal
	}
	result, err := strconv.Atoi(input)
	if err != nil {
		fmt.Println("[" + PrimaryColor("!") + "] [ " + PrimaryColor("The Provided Answer Is Not A Number!") + " ]")
		return AskInt(question, defaultVal)
	}
	return result
}

func AskString(question string, defaultVal string) string {
	fmt.Print("[" + PrimaryColor("+") + "] [ " + PrimaryColor(question) + " ]: ")
	input := ReadTerminal()
	if input == "" {
		fmt.Println("[" + PrimaryColor("-") + "] [ " + PrimaryColor("Using Default Value "+defaultVal) + " ]")
		return defaultVal
	}
	return input
}

func JsonEscape(i string) string {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	// Trim the beginning and trailing " character
	return string(b[1 : len(b)-1])
}

// TrimTime floors a unix timestamp onto the 10-second bucket grid. It moved
// to core/proxy in wave 7 (the clock lives there, and core/utils imports
// core/proxy, so proxy cannot import utils back); this wrapper keeps the
// import path the wave-3 TrimTime tests pin.
func TrimTime(timestamp int) int {
	return proxy.TrimTime(timestamp)
}

func SafeString(str string) string {
	return string([]byte(str))
}

// StageToString renders a suspicion level as the string component that
// core/server/middleware.go appends to the token cache key
// ("<ip><tlsFp><userAgent><hourBucket>" + this), and that the same file prints
// in the "Suspicious request of level ..." block page and in /_bProxy/stats.
//
// It used to be a switch over 1..4 with everything else — including 0 and every
// negative — falling into "5+". susLv 0 is the whitelist verdict and susLv >= 5
// is the block verdict, so the two most opposed outcomes in the request path
// shared a cache key. Concretely: a whitelisted request stores the empty token
// under "<accessKey>5+"; a later request from the same client at susLv 5 finds
// that entry, skips the first switch (and therefore the block that lives in its
// default branch), and reaches the cookie check with encryptedIP == "". That
// check is strings.Contains(cookieHeader, "__bProxy_v="+encryptedIP), which
// with an empty token degenerates to a search for the literal "__bProxy_v=" —
// satisfied by ANY leftover proxy cookie, including the stale
// "_1__bProxy_v=<anything>" the client already has. The blocked request is then
// proxied to the backend. Both the whitelist and the block are attacker-
// reachable through firewall rules and through stage escalation, so this was a
// full bypass of the block verdict, not a theoretical collision.
//
// It is now total and collision-free for cache-key purposes: every level that
// can reach the cache gets its own string. 5 and above still share "5+" because
// that branch returns before anything is cached and the token is only ever a
// display string there.
func StageToString(stage int) string {
	if stage >= 5 {
		return "5+"
	}
	return strconv.Itoa(stage)
}

func closestTo10(n int) int {
	if n == 0 {
		return 10
	}

	if n%10 >= 5 {
		return (n/10 + 1) * 10
	}

	result := n / 10 * 10

	if result == 0 {
		return 10
	}

	return result
}
