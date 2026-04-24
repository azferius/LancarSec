package server

import (
	"bufio"
	"fmt"
	"lancarsec/core/config"
	"lancarsec/core/domains"
	"lancarsec/core/firewall"
	"lancarsec/core/pnc"
	"lancarsec/core/proxy"
	"lancarsec/core/utils"
	"os"
	"strconv"
	"strings"

	"github.com/inancgumus/screen"
)

var helpMode = false

// ReloadConfig is the command-facing wrapper that re-reads config.json and
// re-wires domain state at runtime. The actual work lives in config.Apply
// so the startup path and the reload path cannot drift apart anymore.
func ReloadConfig() {
	config.Apply(config.ModeReload)
}

// commands reads stdin in a loop and dispatches each whitespace-separated
// command to the right action. Every branch ends by repainting the prompt.
func commands() {
	defer pnc.PanicHndl()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		PrintMutex.Lock()
		fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
		fmt.Print("\033[K[ " + utils.PrimaryColor("Command") + " ]: \033[s")

		details := strings.Split(scanner.Text(), " ")

		firewall.DataMu.RLock()
		domainData := domains.DomainsData[proxy.WatchedDomain]
		firewall.DataMu.RUnlock()
		helpMode = false

		switch details[0] {
		case "stage":
			handleStageCommand(details, domainData)
		case "domain":
			handleDomainCommand(details)
		case "add":
			handleAddCommand()
		case "clrlogs":
			handleClrlogsCommand()
		case "reload":
			handleReloadCommand()
		case "help":
			helpMode = true
			repaintLoadingPrompt()
		default:
			repaintPrompt()
		}
		PrintMutex.Unlock()
	}
}

func handleStageCommand(details []string, domainData domains.DomainData) {
	if domainData.Stage == 0 || len(details) < 2 {
		return
	}
	setStage, err := strconv.ParseInt(details[1], 0, 64)
	if err != nil {
		return
	}
	stage := int(setStage)
	if stage == 0 {
		domainData.Stage = 1
		domainData.StageManuallySet = false
	} else {
		domainData.Stage = stage
		domainData.StageManuallySet = true
	}
	firewall.DataMu.Lock()
	domains.DomainsData[proxy.WatchedDomain] = domainData
	firewall.DataMu.Unlock()
}

func handleDomainCommand(details []string) {
	if len(details) < 2 {
		proxy.WatchedDomain = ""
	} else {
		proxy.WatchedDomain = details[1]
	}
	repaintLoadingPrompt()
}

func handleAddCommand() {
	screen.Clear()
	screen.MoveTopLeft()
	utils.AddDomain()
	repaintLoadingPrompt()
	ReloadConfig()
}

func handleClrlogsCommand() {
	screen.Clear()
	screen.MoveTopLeft()
	if proxy.WatchedDomain == "" {
		for _, domain := range domains.Domains {
			firewall.DataMu.Lock()
			utils.ClearLogs(domain)
			firewall.DataMu.Unlock()
		}
		fmt.Println("[ " + utils.PrimaryColor("Clearing Logs All Domains ") + " ] ...")
	} else {
		firewall.DataMu.Lock()
		utils.ClearLogs(proxy.WatchedDomain)
		firewall.DataMu.Unlock()
		fmt.Println("[ " + utils.PrimaryColor("Clearing Logs For "+proxy.WatchedDomain) + " ] ...")
	}
	fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
}

func handleReloadCommand() {
	screen.Clear()
	screen.MoveTopLeft()
	fmt.Println("[ " + utils.PrimaryColor("Reloading Proxy") + " ] ...")
	ReloadConfig()
	fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
}

func repaintLoadingPrompt() {
	screen.Clear()
	screen.MoveTopLeft()
	fmt.Println("[ " + utils.PrimaryColor("Loading") + " ] ...")
	fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
}

func repaintPrompt() {
	screen.Clear()
	screen.MoveTopLeft()
	fmt.Println("\033[" + fmt.Sprint(12+proxy.MaxLogLength) + ";1H")
	fmt.Print("[ " + utils.PrimaryColor("Command") + " ]: \033[s")
}
