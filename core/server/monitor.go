package server

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/inancgumus/screen"
	"github.com/shirou/gopsutil/cpu"
	"golang.org/x/term"

	"lancarsec/core/domains"
	"lancarsec/core/firewall"
	"lancarsec/core/pnc"
	"lancarsec/core/proxy"
	"lancarsec/core/utils"
)

var PrintMutex = &sync.Mutex{}

// maxRequestLogEntries caps the per-domain RequestLogger slice so a
// sustained multi-hour attack — where BufferCooldown keeps resetting and
// never ticks down to zero — cannot grow an unbounded slice and leak memory.
// 600 entries at 1-second granularity gives 10 minutes of history, which is
// the useful window for the post-attack Discord chart anyway.
const maxRequestLogEntries = 600

func appendRequestLog(logs []domains.RequestLog, entry domains.RequestLog) []domains.RequestLog {
	logs = append(logs, entry)
	if len(logs) > maxRequestLogEntries {
		// Drop the oldest half at once rather than one-at-a-time so we don't
		// realloc on every write when the slice is at capacity.
		drop := len(logs) - maxRequestLogEntries
		copy(logs, logs[drop:])
		logs = logs[:len(logs)-drop]
	}
	return logs
}

// Monitor owns the terminal UI loop: it also kicks off the supporting
// background goroutines (command reader, cache cleaner, ratelimit evaluator,
// OTP rotator) once when the proxy starts.
func Monitor() {
	defer pnc.PanicHndl()

	PrintMutex.Lock()
	screen.Clear()
	screen.MoveTopLeft()
	PrintMutex.Unlock()

	now := time.Now()
	proxy.SetRuntimeClock(now)

	go commands()
	go firewall.ClearProxyCache()
	go generateOTPSecrets()
	go firewall.EvaluateRatelimit()

	PrintMutex.Lock()
	fmt.Println("\033[" + fmt.Sprint(11+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
	PrintMutex.Unlock()

	for {
		PrintMutex.Lock()
		tempWidth, tempHeight, _ := term.GetSize(int(os.Stdout.Fd()))
		if tempHeight != proxy.THeight || tempWidth+18 != proxy.TWidth {
			proxy.TWidth = tempWidth + 18
			proxy.THeight = tempHeight
			pHeight := tempHeight - 15
			if pHeight < 0 {
				proxy.MaxLogLength = 0
			} else {
				proxy.MaxLogLength = pHeight
			}
			screen.Clear()
			screen.MoveTopLeft()
			fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
			fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
		}
		utils.ClearScreen(proxy.MaxLogLength)
		fmt.Print("\033[1;1H")

		firewall.DataMu.Lock()
		for name, data := range domains.DomainsData {
			checkAttack(name, data)
		}
		firewall.DataMu.Unlock()

		printStats()

		PrintMutex.Unlock()
		time.Sleep(1 * time.Second)
	}
}

// checkAttack advances the per-domain stage state machine based on live r/s.
// Only call with firewall.DataMu held — the caller iterates DomainsData.
func checkAttack(domainName string, domainData domains.DomainData) {
	if domainName == "debug" {
		return
	}

	// Read the atomic counters (middleware increments them without DataMu)
	// and mirror them into the DomainData struct so the rest of the logic
	// and the UI keep working unchanged.
	ctr := domains.CountersFor(domainName)
	domainData.TotalRequests = int(ctr.Total.Load())
	domainData.BypassedRequests = int(ctr.Bypassed.Load())
	domainData.RequestsPerSecond = domainData.TotalRequests - domainData.PrevRequests
	domainData.RequestsBypassedPerSecond = domainData.BypassedRequests - domainData.PrevBypassed
	domainData.PrevRequests = domainData.TotalRequests
	domainData.PrevBypassed = domainData.BypassedRequests

	if !domainData.StageManuallySet || domainData.BufferCooldown > 0 {
		if domainData.BufferCooldown > 0 {
			if domainData.RequestsPerSecond > domainData.PeakRequestsPerSecond {
				domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
			}
			if domainData.RequestsBypassedPerSecond > domainData.PeakRequestsBypassedPerSecond {
				domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
			}
			domainData.RequestLogger = appendRequestLog(domainData.RequestLogger, domains.RequestLog{
				Time:     time.Now(),
				Allowed:  domainData.RequestsBypassedPerSecond,
				Total:    domainData.RequestsPerSecond,
				CpuUsage: proxy.GetCPUUsage(),
			})
		}

		settingQuery, ok := domains.DomainsMap.Load(domainName)
		if !ok {
			return
		}
		domainSettings := settingQuery.(domains.DomainSettings)

		// Adaptive PoW difficulty: when the domain is actively bypassed,
		// bump the Stage 2 difficulty so each attacker-client pays more
		// CPU for a pass. Normal visitors during idle traffic get the
		// configured base, so there's no UX regression.
		firewall.SetDifficulty(domainName, firewall.AdaptDifficulty(
			domainName,
			domainData.Stage2Difficulty,
			domainData.BypassAttack,
			domainData.RequestsBypassedPerSecond,
			domainSettings.BypassStage1,
		))

		if !domainData.BypassAttack && !domainData.RawAttack && domainData.BufferCooldown > 0 {
			domainData.BufferCooldown--
			if domainData.BufferCooldown == 0 {
				go utils.SendWebhook(domainData, domainSettings, 1)
				domainData.PeakRequestsPerSecond = 0
				domainData.PeakRequestsBypassedPerSecond = 0
				domainData.RequestLogger = []domains.RequestLog{}
			}
		}

		switch domainData.Stage {
		case 1:
			if domainData.RequestsBypassedPerSecond > domainSettings.BypassStage1 && !domainData.BypassAttack {
				domainData.BypassAttack = true
				domainData.Stage = 2
				if domainData.BufferCooldown == 0 {
					domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
					domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
					domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
						Time:     time.Now(),
						Allowed:  domainData.RequestsBypassedPerSecond,
						Total:    domainData.RequestsPerSecond,
						CpuUsage: proxy.GetCPUUsage(),
					})
					go utils.SendWebhook(domainData, domainSettings, 0)
				}
				domainData.BufferCooldown = 10
			}
		case 2:
			if domainData.RequestsBypassedPerSecond > domainSettings.BypassStage2 {
				domainData.Stage = 3
			} else if domainData.RequestsBypassedPerSecond < domainSettings.DisableBypassStage2 && domainData.RequestsPerSecond < domainSettings.DisableRawStage2 && domainData.BypassAttack {
				domainData.BypassAttack = false
				domainData.RawAttack = false
				domainData.Stage = 1
			}
		case 3:
			if domainData.RequestsBypassedPerSecond < domainSettings.DisableBypassStage3 && domainData.RequestsPerSecond < domainSettings.DisableRawStage3 {
				domainData.Stage = 2
			}
		}

		if domainData.RequestsPerSecond > domainSettings.DisableRawStage2 && !domainData.RawAttack && !domainData.BypassAttack {
			domainData.RawAttack = true
			if domainData.BufferCooldown == 0 {
				domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
				domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
				domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
					Time:     time.Now(),
					Allowed:  domainData.RequestsBypassedPerSecond,
					Total:    domainData.RequestsPerSecond,
					CpuUsage: proxy.GetCPUUsage(),
				})
				go utils.SendWebhook(domainData, domainSettings, 0)
			}
			domainData.BufferCooldown = 10
		} else if domainData.RequestsPerSecond < domainSettings.DisableRawStage2 && domainData.RawAttack && !domainData.BypassAttack {
			domainData.RawAttack = false
		}
	}

	domains.DomainsData[domainName] = domainData
}

func printStats() {
	now := time.Now()
	proxy.SetRuntimeClock(now)

	result, err := cpu.Percent(0, false)
	switch {
	case err != nil:
		proxy.SetCPUUsage("ERR")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Cpu Usage") + " ] > [ " + utils.PrimaryColor(err.Error()) + " ]")
	case len(result) > 0:
		proxy.SetCPUUsage(fmt.Sprintf("%.2f", result[0]))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Cpu Usage") + " ] > [ " + utils.PrimaryColor(proxy.GetCPUUsage()) + " ]")
	default:
		proxy.SetCPUUsage("ERR_S0")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Cpu Usage") + " ] > [ " + utils.PrimaryColor("100.00 ( Speculated )") + " ]")
	}

	var ramStats runtime.MemStats
	runtime.ReadMemStats(&ramStats)
	proxy.SetRAMUsage(fmt.Sprintf("%.2f", float64(ramStats.Alloc)/float64(ramStats.Sys)*100))

	fmt.Println("")

	watchedDomain := proxy.GetWatchedDomain()
	firewall.DataMu.RLock()
	domainData := domains.DomainsData[watchedDomain]
	firewall.DataMu.RUnlock()

	switch {
	case domainData.Stage == 0 && watchedDomain != "debug":
		if watchedDomain != "" {
			fmt.Println("[" + utils.PrimaryColor("!") + "] [ " + utils.PrimaryColor("Domain \""+watchedDomain+"\" Not Found") + " ]")
			fmt.Println("")
		}
		fmt.Println("[" + utils.PrimaryColor("Available Domains") + "]")
		counter := 0
		for _, dName := range domains.LoadDomainNames() {
			if counter < proxy.MaxLogLength {
				fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor(dName) + " ]")
				counter++
			}
		}
	case helpMode:
		fmt.Println("[" + utils.PrimaryColor("Available Commands") + "]")
		fmt.Println("")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("help") + " ]: " + utils.PrimaryColor("Displays all available commands. More detailed information can be found at ") + "https://sec.splay.id/docs#commands")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("stage") + " ]: " + utils.PrimaryColor("Usage: ") + "stage [number] " + utils.PrimaryColor("Locks the stage to the specified number. Use ") + "stage 0 " + utils.PrimaryColor("to unlock the stage"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("domain") + " ]: " + utils.PrimaryColor("Usage: ") + "domain [name] " + utils.PrimaryColor("Switch between your domains. Type only ") + "domain " + utils.PrimaryColor("to list all available domains"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("add") + " ]: " + utils.PrimaryColor("Usage: ") + "add " + utils.PrimaryColor("Starts a dialouge to add another domain to the proxy"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("clrlogs") + " ]: " + utils.PrimaryColor("Usage: ") + "clrlogs " + utils.PrimaryColor("Clears all logs for the current domain"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("reload") + " ]: " + utils.PrimaryColor("Usage: ") + "reload " + utils.PrimaryColor("Reload your proxy in order for changes in your ") + "config.json " + utils.PrimaryColor("to take effect"))
	default:
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Domain") + " ] > [ " + utils.PrimaryColor(watchedDomain) + " ]")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Stage") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.Stage)) + " ]")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Stage Locked") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.StageManuallySet)) + " ]")
		fmt.Println("")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Total") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.RequestsPerSecond)+" r/s") + " ]")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Bypassed") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.RequestsBypassedPerSecond)+" r/s") + " ]")
		fmt.Println("")
		fmt.Println("[ " + utils.PrimaryColor("Latest Logs") + " ]")
		utils.ReadLogs(watchedDomain)
	}

	utils.MoveInputLine()
}
