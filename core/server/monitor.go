package server

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/azferius/lancarsec/core/screen"

	"github.com/shirou/gopsutil/v4/cpu"
	"golang.org/x/term"

	"github.com/azferius/lancarsec/core/config"
	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/firewall"
	"github.com/azferius/lancarsec/core/pnc"
	"github.com/azferius/lancarsec/core/proxy"
	"github.com/azferius/lancarsec/core/utils"
)

var (
	PrintMutex = &sync.Mutex{}
	helpMode   = false
)

// AddDomain is the interactive add-a-domain wizard the TUI's `add` command
// runs. It is config.AddDomain, wired by main at startup.
//
// It is a variable rather than a direct call because core/config imports
// core/server (init.go needs server.RoundTripper), so core/server importing
// core/config would be an import cycle. Verified with
// `go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./core/config`.
//
// This existed as a second, drifted copy of the wizard in core/utils until
// wave 4: utils.AddDomain omitted the Stage2Difficulty question, so every
// domain added from the running TUI got Stage2Difficulty 0 -- the same defect
// the reload path has. Deleting that copy is what makes the two paths agree.
//
// Once core/transport lands and core/config stops importing core/server, this
// can collapse back into a plain `config.AddDomain()` call at the use site.
var AddDomain func() error

// monitorJobs are the long-lived background workers Monitor starts. They are a
// table rather than four `go f()` statements so that adding a worker means
// adding a row -- there is no longer a launch site where someone can drop in an
// unsupervised goroutine without it being obvious.
//
// Before wave 4 all four were launched bare. Three of them had
// `defer pnc.PanicHndl()` inside, which writes crash.log and then RE-RAISES, so
// a panic still killed the process; evaluateRatelimit had no handler at all, so
// a panic there killed the process with no record of why. Either way the
// ratelimit clock -- the thing that rebuilds the sliding-window totals and
// prefills the buckets the request path writes into -- died with it.
//
// pnc.Supervise records the panic and restarts the worker with a capped
// exponential backoff instead. The inner PanicHndl calls are left in place:
// they capture the stack at the original panic site, which is strictly more
// information than the supervisor's own frame, and their re-raise is now caught
// one level up rather than reaching the runtime.
var monitorJobs = []struct {
	name string
	run  func()
}{
	// Responsible for handling user-commands
	{"commands", commands},
	// Responsible for clearing outdated cache and data
	{"clearProxyCache", clearProxyCache},
	// Responsible for generating non-bruteforceable secrets
	{"generateOTPSecrets", generateOTPSecrets},
	// Responsible for keeping track of ratelimit
	{"evaluateRatelimit", evaluateRatelimit},
	// Responsible for publishing the request-path clock (wave 7)
	{"clock", clock},
}

func Monitor() {

	defer pnc.PanicHndl()

	PrintMutex.Lock()
	screen.Clear()
	screen.MoveTopLeft()
	PrintMutex.Unlock()

	// Publish the clock once synchronously before any job -- and therefore
	// before Serve is allowed to start -- so the first request reads a real
	// clock and a real 10-second bucket, never a zero one. The clock job takes over
	// from here.
	proxy.UpdateClock(time.Now())

	// Publish one OTP set synchronously before any job — and therefore before
	// Serve is allowed to start — so the first request cannot be derived
	// against an empty bucket. generateOTPSecrets republishes the same value
	// immediately; publishOTP is idempotent within an hour.
	publishOTP(time.Now())

	for _, job := range monitorJobs {
		pnc.Supervise(job.name, job.run)
	}

	PrintMutex.Lock()
	fmt.Println("\033[" + fmt.Sprint(11+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
	PrintMutex.Unlock()
	for {
		PrintMutex.Lock()
		tempWidth, tempHeight, _ := term.GetSize(int(os.Stdout.Fd()))
		proxy.TWidth = tempWidth + 18
		if tempHeight != proxy.THeight || tempWidth+18 != proxy.TWidth {
			proxy.THeight = tempHeight

			pHeight := tempHeight - 15
			proxy.MaxLogLength = max(pHeight, 0)

			screen.Clear()
			screen.MoveTopLeft()
			fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
			fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
		}
		utils.ClearScreen(proxy.MaxLogLength)
		fmt.Print("\033[1;1H")

		firewall.Mutex.Lock()
		for name, data := range domains.DomainsData {
			checkAttack(name, data)
		}
		firewall.Mutex.Unlock()

		printStats()

		PrintMutex.Unlock()
		time.Sleep(1 * time.Second)
	}
}

// Only run this inside of a locked thread to avoid false reports
func checkAttack(domainName string, domainData domains.DomainData) {

	if domainName == "debug" {
		return
	}

	domainData.RequestsPerSecond = domainData.TotalRequests - domainData.PrevRequests
	domainData.RequestsBypassedPerSecond = domainData.BypassedRequests - domainData.PrevBypassed

	domainData.PrevRequests = domainData.TotalRequests
	domainData.PrevBypassed = domainData.BypassedRequests

	if !domainData.StageManuallySet || (domainData.BufferCooldown > 0) {

		// Log requests if a bypassing or raw attack is ongoing
		if domainData.BufferCooldown > 0 {
			if domainData.RequestsPerSecond > domainData.PeakRequestsPerSecond {
				domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
			}
			if domainData.RequestsBypassedPerSecond > domainData.PeakRequestsBypassedPerSecond {
				domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
			}
			domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
				Time:     time.Now(),
				Allowed:  domainData.RequestsBypassedPerSecond,
				Total:    domainData.RequestsPerSecond,
				CpuUsage: proxy.CpuUsage(),
			})
		}

		settingQuery, _ := domains.DomainsMap.Load(domainName)
		domainSettings := settingQuery.(domains.DomainSettings)

		if !domainData.BypassAttack && !domainData.RawAttack && (domainData.BufferCooldown > 0) {
			domainData.BufferCooldown--

			if domainData.BufferCooldown == 0 {
				go utils.SendWebhook(domainData, domainSettings, int(1))
				domainData.PeakRequestsPerSecond = 0
				domainData.PeakRequestsBypassedPerSecond = 0
				domainData.RequestLogger = []domains.RequestLog{}
			}
		}

		switch domainData.Stage {
		case 1:
			// A Bypassing Attack Started
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
						CpuUsage: proxy.CpuUsage(),
					})
					go utils.SendWebhook(domainData, domainSettings, int(0))
				}
				// Start/Set cooldown
				domainData.BufferCooldown = 10
			}
		case 2:
			// Stage 2 is getting bypassed
			if domainData.RequestsBypassedPerSecond > domainSettings.BypassStage2 {
				domainData.Stage = 3

				// Stage 2 is no longer getting bypassed
			} else if domainData.RequestsBypassedPerSecond < domainSettings.DisableBypassStage2 && domainData.RequestsPerSecond < domainSettings.DisableRawStage2 && domainData.BypassAttack {
				domainData.BypassAttack = false
				domainData.RawAttack = false
				domainData.Stage = 1
			}
		case 3:
			// Stage 3 is no longer getting bypassed
			if domainData.RequestsBypassedPerSecond < domainSettings.DisableBypassStage3 && domainData.RequestsPerSecond < domainSettings.DisableRawStage3 {
				domainData.Stage = 2
			}
		}

		// An attack that didnt bypass was started
		if domainData.RequestsPerSecond > domainSettings.DisableRawStage2 && !domainData.RawAttack && !domainData.BypassAttack {
			domainData.RawAttack = true

			if domainData.BufferCooldown == 0 {
				domainData.PeakRequestsPerSecond = domainData.RequestsPerSecond
				domainData.PeakRequestsBypassedPerSecond = domainData.RequestsBypassedPerSecond
				domainData.RequestLogger = append(domainData.RequestLogger, domains.RequestLog{
					Time:     time.Now(),
					Allowed:  domainData.RequestsBypassedPerSecond,
					Total:    domainData.RequestsPerSecond,
					CpuUsage: proxy.CpuUsage(),
				})
				go utils.SendWebhook(domainData, domainSettings, int(0))
			}

			//Set/Start cooldown
			domainData.BufferCooldown = 10
		} else if domainData.RequestsPerSecond < domainSettings.DisableRawStage2 && domainData.RawAttack && !domainData.BypassAttack {
			domainData.RawAttack = false
		}

	}

	domains.DomainsData[domainName] = domainData
}

func printStats() {

	// The clock used to be rewritten here, inside the rendering loop. That is
	// the defect wave 7 removes: this loop is serialised on PrintMutex and on
	// every stdout write, so a blocked console froze the clock, the sliding
	// window and the sweeper with it. The clock is now owned by the clock job.
	//
	// WAVE 7: the CPU/RAM gauges left this loop for the same reason. They were
	// plain globals written here and read by the cache sweeper (under
	// firewall.Mutex), the admin API handlers and the webhook builder (under
	// no lock at all) -- writer and readers synchronised by different mutexes,
	// i.e. by nothing. printStats remains the only production writer, via
	// proxy.SetCpuUsage/SetRamUsage; everything else reads the atomics
	// lock-free.

	result, err := cpu.Percent(0, false)
	if err != nil {
		proxy.SetCpuUsage("ERR")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Cpu Usage") + " ] > [ " + utils.PrimaryColor(err.Error()) + " ]")
	} else if len(result) > 0 {
		usage := fmt.Sprintf("%.2f", result[0])
		proxy.SetCpuUsage(usage)
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Cpu Usage") + " ] > [ " + utils.PrimaryColor(usage) + " ]")
	} else {
		proxy.SetCpuUsage("ERR_S0")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Cpu Usage") + " ] > [ " + utils.PrimaryColor("100.00 ( Speculated )") + " ]")
	}

	//Not printed yet but calculated ram usage in %

	var ramStats runtime.MemStats
	runtime.ReadMemStats(&ramStats)

	// Calculate the current memory usage in percentage
	proxy.SetRamUsage(fmt.Sprintf("%.2f", float64(ramStats.Alloc)/float64(ramStats.Sys)*100))

	fmt.Println("")

	firewall.Mutex.RLock()
	domainData := domains.DomainsData[proxy.WatchedDomain]
	firewall.Mutex.RUnlock()

	if domainData.Stage == 0 && proxy.WatchedDomain != "debug" {
		if proxy.WatchedDomain != "" {
			fmt.Println("[" + utils.PrimaryColor("!") + "] [ " + utils.PrimaryColor("Domain \""+proxy.WatchedDomain+"\" Not Found") + " ]")
			fmt.Println("")
		}
		fmt.Println("[" + utils.PrimaryColor("Available Domains") + "]")
		counter := 0
		for _, dName := range domains.Domains {
			if counter < proxy.MaxLogLength {
				fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor(dName) + " ]")
				counter++
			}
		}
	} else if helpMode {
		fmt.Println("[" + utils.PrimaryColor("Available Commands") + "]")
		fmt.Println("")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("help") + " ]: " + utils.PrimaryColor("Displays all available commands. More detailed information can be found at ") + "https://github.com/41Baloo/balooProxy#commands")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("stage") + " ]: " + utils.PrimaryColor("Usage: ") + "stage [number] " + utils.PrimaryColor("Locks the stage to the specified number. Use ") + "stage 0 " + utils.PrimaryColor("to unlock the stage"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("domain") + " ]: " + utils.PrimaryColor("Usage: ") + "domain [name] " + utils.PrimaryColor("Switch between your domains. Type only ") + "domain " + utils.PrimaryColor("to list all available domains"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("add") + " ]: " + utils.PrimaryColor("Usage: ") + "add " + utils.PrimaryColor("Starts a dialouge to add another domain to the proxy"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("clrlogs") + " ]: " + utils.PrimaryColor("Usage: ") + "clrlogs " + utils.PrimaryColor("Clears all logs for the current domain"))
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("reload") + " ]: " + utils.PrimaryColor("Usage: ") + "reload " + utils.PrimaryColor("Reload your proxy in order for changes in your ") + "config.json " + utils.PrimaryColor("to take effect"))
	} else {

		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Domain") + " ] > [ " + utils.PrimaryColor(proxy.WatchedDomain) + " ]")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Stage") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.Stage)) + " ]")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Stage Locked") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.StageManuallySet)) + " ]")
		fmt.Println("")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Total") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.RequestsPerSecond)+" r/s") + " ]")
		fmt.Println("[" + utils.PrimaryColor("+") + "] [ " + utils.PrimaryColor("Bypassed") + " ] > [ " + utils.PrimaryColor(fmt.Sprint(domainData.RequestsBypassedPerSecond)+" r/s") + " ]")

		fmt.Println("")
		fmt.Println("[ " + utils.PrimaryColor("Latest Logs") + " ]")

		utils.ReadLogs(proxy.WatchedDomain)
	}

	utils.MoveInputLine()
}

func commands() {

	defer pnc.PanicHndl()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		if scanner.Scan() {

			PrintMutex.Lock()
			fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
			fmt.Print("\033[K[ " + utils.PrimaryColor("Command") + " ]: \033[s")

			input := scanner.Text()
			details := strings.Split(input, " ")

			firewall.Mutex.RLock()
			domainData := domains.DomainsData[proxy.WatchedDomain]
			firewall.Mutex.RUnlock()
			helpMode = false

			switch details[0] {
			case "stage":

				if domainData.Stage == 0 {
					break
				}
				if !(len(details) > 1) {
					break
				}
				setStage, err := strconv.ParseInt(details[1], 0, 64)
				if err != nil {
					break
				}
				stage := int(setStage)
				if stage == 0 {
					domainData.Stage = 1
					domainData.StageManuallySet = false

					firewall.Mutex.Lock()
					domains.DomainsData[proxy.WatchedDomain] = domainData
					firewall.Mutex.Unlock()
				} else {
					domainData.Stage = stage
					domainData.StageManuallySet = true

					firewall.Mutex.Lock()
					domains.DomainsData[proxy.WatchedDomain] = domainData
					firewall.Mutex.Unlock()
				}
			case "domain":
				if len(details) < 2 {
					proxy.WatchedDomain = ""
				} else {
					proxy.WatchedDomain = details[1]
				}

				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.PrimaryColor("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
			case "add":
				screen.Clear()
				screen.MoveTopLeft()
				if AddDomain == nil {
					fmt.Println("[ " + utils.PrimaryColor("add is unavailable: the domain wizard was not wired at startup") + " ]")
					fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
					fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
					break
				}
				if err := AddDomain(); err != nil {
					fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ " + utils.PrimaryColor("Add Domain Failed: "+err.Error()) + " ]")
					time.Sleep(3 * time.Second)
					break
				}
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.PrimaryColor("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
				ReloadConfig()
			case "clrlogs":
				screen.Clear()
				screen.MoveTopLeft()
				if proxy.WatchedDomain == "" {
					for _, domain := range domains.Domains {
						firewall.Mutex.Lock()
						utils.ClearLogs(domain)
						firewall.Mutex.Unlock()
					}
					fmt.Println("[ " + utils.PrimaryColor("Clearing Logs All Domains ") + " ] ...")
				} else {
					firewall.Mutex.Lock()
					utils.ClearLogs(proxy.WatchedDomain)
					firewall.Mutex.Unlock()
					fmt.Println("[ " + utils.PrimaryColor("Clearing Logs For "+proxy.WatchedDomain) + " ] ...")
				}
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
			case "reload":
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.PrimaryColor("Reloading Proxy") + " ] ...")
				ReloadConfig()
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
			case "help":
				helpMode = true
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("[ " + utils.PrimaryColor("Loading") + " ] ...")
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
			default:
				screen.Clear()
				screen.MoveTopLeft()
				fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
				fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
			}
			PrintMutex.Unlock()
		}
	}
}

// ReloadConfig re-reads config.json and converges the running proxy onto it.
//
// The body of this function used to be a hand-maintained second copy of
// config.Load and had drifted from it in eight places - most seriously it
// rebuilt every DomainData without Stage2Difficulty, so after any `reload` the
// stage-2 page printed the exact token it was asking the client to find. It is
// now a one-line call into the single pipeline in core/config.
//
// A failed reload leaves the proxy running its previous configuration. It used
// to panic instead, which killed the command goroutine while it still held
// PrintMutex: the terminal UI froze permanently and the operator lost the only
// control channel the proxy has.
func ReloadConfig() {
	if err := config.Reload(); err != nil {
		fmt.Println("[ " + utils.PrimaryColor("!") + " ] [ " + utils.PrimaryColor("Reload Failed: "+err.Error()) + " ]")
		fmt.Println("[ " + utils.PrimaryColor("+") + " ] [ " + utils.PrimaryColor("The Previous Configuration Is Still Running") + " ]")
		// The monitor repaints the whole screen once a second, so without this
		// the operator never gets to read why the reload was refused. The caller
		// already owns PrintMutex, so this only delays the next repaint.
		time.Sleep(3 * time.Second)
	}
}

func clearProxyCache() {

	defer pnc.PanicHndl()

	for {
		//Clear logs and maps every 2 minutes. (I know this is a lazy way to do it, tho for now it seems to be the most efficient and fast way to go about it)
		firewall.Mutex.Lock()

		proxyCpuUsage, pcuErr := strconv.ParseFloat(proxy.CpuUsage(), 32)
		if pcuErr != nil {
			proxyCpuUsage = 0
		}

		proxyMemUsage, pmuErr := strconv.ParseFloat(proxy.RamUsage(), 32)
		if pmuErr != nil {
			proxyMemUsage = 0
		}

		// Only clear if proxy isnt under attack / memory is running out
		if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 {
			firewall.CacheIps.Range(func(key, value any) bool {
				firewall.CacheIps.Delete(key)
				return true
			})
		}
		// Same for here
		imgCachelen := 0
		firewall.CacheImgs.Range(func(key, value any) bool {
			imgCachelen++
			return true
		})
		if (proxyCpuUsage < 15 && proxyMemUsage > 25) || proxyMemUsage > 95 {
			firewall.CacheImgs.Range(func(key, value any) bool {
				firewall.CacheImgs.Delete(key)
				return true
			})
		}
		firewall.Mutex.Unlock()
		time.Sleep(2 * time.Minute)
	}
}

// Iterate through the slider every 5 seconds
func evaluateRatelimit() {
	for {

		// Read the clock once per pass, off the atomic publisher. The reads
		// below must not straddle a clock tick.
		now := int(proxy.LastSecondTimestamp())
		last10 := int(proxy.Last10SecondTimestamp())

		firewall.Mutex.Lock()
		//Initialise Maps before they're ever written, as to save if statements during potential attack
		for i := last10; i < last10+120; i = i + 10 {
			if firewall.WindowAccessIps[i] == nil {
				//log.Printf("Set AccessIPs Windows For %d", i)
				firewall.WindowAccessIps[i] = map[string]int{}
			}
			if firewall.WindowAccessIpsCookie[i] == nil {
				//log.Printf("Set AccessIPsCookie Windows For %d", i)
				firewall.WindowAccessIpsCookie[i] = map[string]int{}
			}
			if firewall.WindowUnkFps[i] == nil {
				//log.Printf("Set AccessUnkFps Windows For %d", i)
				firewall.WindowUnkFps[i] = map[string]int{}
			}
		}

		// Delete outdated records & calculate requests for every ip
		firewall.AccessIps = map[string]int{}
		for windowTime, accessIPs := range firewall.WindowAccessIps {
			if utils.TrimTime(windowTime)+proxy.RatelimitWindow < now {
				//log.Printf("Deleting AccessIPs Windows For %d", windowTime)
				delete(firewall.WindowAccessIps, windowTime)
			} else {
				for IP, requests := range accessIPs {
					firewall.AccessIps[IP] += requests
				}
			}
		}
		firewall.AccessIpsCookie = map[string]int{}
		for windowTime, accessIPsCookie := range firewall.WindowAccessIpsCookie {
			if utils.TrimTime(windowTime)+proxy.RatelimitWindow < now {
				//log.Printf("Deleting AccessIPsCookie Windows For %d", windowTime)
				delete(firewall.WindowAccessIpsCookie, windowTime)
			} else {
				for IP, requests := range accessIPsCookie {
					firewall.AccessIpsCookie[IP] += requests
				}
			}
		}
		firewall.UnkFps = map[string]int{}
		for windowTime, unkFps := range firewall.WindowUnkFps {
			if utils.TrimTime(windowTime)+proxy.RatelimitWindow < now {
				//log.Printf("Deleting AccessUnkFps Windows For %d", windowTime)
				delete(firewall.WindowUnkFps, windowTime)
			} else {
				for IP, requests := range unkFps {
					firewall.UnkFps[IP] += requests
				}
			}
		}
		firewall.Mutex.Unlock()
		proxy.Initialised = true

		//log.Printf("I Ran. I'm supposed to run every 5 seconds. If that didn't happen we're in deep shit")
		time.Sleep(5 * time.Second)
	}
}

// clock publishes the request-path clock once per second.
//
// Wave 7: this job exists so the clock is no longer written by printStats, the
// terminal renderer. printStats runs under PrintMutex and every stdout write
// serialises against it, so a blocked stdout -- journald, a full pipe, a
// stopped console -- used to freeze the clock, and with it the sliding-window
// bucket every request increments and the "now" the sweeper compares against.
// Ratelimiting then stopped recovering for as long as stdout stayed blocked.
//
// This goroutine deliberately touches nothing but proxy.UpdateClock. It does
// not print, and it does not take PrintMutex.
func clock() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		proxy.UpdateClock(time.Now())
	}
}

// otpRotationSkew is how far past the hour boundary the rotation wakes up. It
// absorbs timer granularity and coarse clock resolution so a wake-up that fires
// a millisecond early does not format the hour that is about to end and then
// sleep a full further hour on the wrong bucket.
const otpRotationSkew = 250 * time.Millisecond

// publishOTP derives the three challenge OTPs for the aligned UTC hour that t
// falls in, and publishes them together with that bucket string as one
// immutable set.
//
// Deriving from an aligned bucket, in UTC, is what lets independent instances
// agree. The previous code slept a fixed hour from whenever the process
// happened to start and keyed off a LOCAL calendar date: two instances behind
// one load balancer therefore rotated at different wall-clock instants, and any
// instance in a different timezone used a different key for most of the day. A
// client bounced between them by the balancer derived a token under instance
// A's OTP and failed instance B's check, so it was re-challenged on every
// switch — a self-inflicted challenge storm that got worse the more instances
// were added. Alignment removes the dependency on start time entirely: every
// instance in the fleet computes the same bucket for the same instant.
func publishOTP(t time.Time) {
	bucket := t.UTC().Format(proxy.OTPBucketLayout)

	proxy.StoreOTP(proxy.OTP{
		Hour:    bucket,
		Cookie:  utils.EncryptSha(proxy.CookieSecret, bucket),
		JS:      utils.EncryptSha(proxy.JSSecret, bucket),
		Captcha: utils.EncryptSha(proxy.CaptchaSecret, bucket),
	})
}

// nextOTPRotation returns how long to sleep from t to just past the next
// wall-clock hour boundary. Split out from the loop so the alignment is
// testable without waiting an hour.
func nextOTPRotation(t time.Time) time.Duration {
	utc := t.UTC()
	d := utc.Truncate(time.Hour).Add(time.Hour).Sub(utc) + otpRotationSkew
	if d <= 0 {
		// Unreachable for a sane clock: Truncate/Add always lands strictly
		// after utc. Kept so a clock jump can never spin this loop.
		return time.Second
	}
	return d
}

// rotateOTPOnce publishes the set for now and returns how long to sleep before
// the next rotation.
//
// It takes ONE instant and uses it for both halves on purpose. Reading the
// clock twice — publishOTP(time.Now()) followed by
// nextOTPRotation(time.Now()) — skips a whole bucket whenever the two reads
// straddle an hour boundary: publish at 12:59:59.999 stores the 12:00 set, then
// the second read at 13:00:00.001 schedules the next wake for 14:00, so the
// 13:00 bucket is never published and every client is challenged against a
// stale OTP for an hour. One instant makes that unrepresentable.
func rotateOTPOnce(now time.Time) time.Duration {
	publishOTP(now)
	return nextOTPRotation(now)
}

func generateOTPSecrets() {

	defer pnc.PanicHndl()

	// The OTPs are keyed on an ALIGNED UTC hour bucket, so every instance
	// behind the same load balancer derives identical secrets for the same
	// instant no matter when it was started or what timezone it runs in. See
	// publishOTP for what the unaligned, local-date version cost.

	for {
		time.Sleep(rotateOTPOnce(time.Now()))
	}
}
