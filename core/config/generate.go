package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/azferius/lancarsec/core/domains"
	"github.com/azferius/lancarsec/core/utils"
)

// Generate writes a fresh config.json from an interactive dialogue and seeds it
// with one domain. It no longer installs the generated configuration into
// the live config: Load re-runs the whole pipeline over what was written, so
// nothing reaches the running proxy without being validated first.
func Generate() error {

	fmt.Println("[ " + utils.PrimaryColor("No Configuration File Found") + " ]")
	fmt.Println("[ " + utils.PrimaryColor("Configuring Proxy Now") + " ]")
	fmt.Println("")

	gConfig := domains.Configuration{
		Proxy: domains.Proxy{
			Cloudflare:  utils.AskBool("Use This Proxy With Cloudflare? (y/N)", false),
			AdminSecret: utils.RandomString(25),
			APISecret:   utils.RandomString(30),
			Timeout: domains.TimeoutSettings{
				Idle:       utils.AskInt("How Many Seconds Should An Indle Connection Be Kept Open?", 3),
				Read:       utils.AskInt("How Many Seconds Should A Reading Connection Be Kept Open?", 5),
				Write:      utils.AskInt("How Many Seconds Should A Writing Connection Be Kept Open?", 5),
				ReadHeader: utils.AskInt("How Many Seconds Should Be Allowed To Read A Connections Header?", 5),
			},
			Secrets: map[string]string{
				"cookie":     utils.RandomString(20),
				"javascript": utils.RandomString(20),
				"captcha":    utils.RandomString(20),
			},
			Ratelimits: map[string]int{
				"requests":           utils.AskInt("After How Many Requests From An IP Within 2 Minutes Should It Be Blocked?", 1000),
				"unknownFingerprint": utils.AskInt("After How Many Requests From An Unknown Fingerprint Within 2 Minutes Should It Be Blocked?", 150),
				"challengeFailures":  utils.AskInt("After How Many Failed Attempts At Solving A Challenge From An IP Within 2 Minutes Should It Be Blocked?", 40),
				"noRequestsSent":     utils.AskInt("After How Many TCP Connection Attempts Without Sending A Http Request From An IP Within 2 Minutes Should It Be Blocked?", 10),
			},
		},
		Domains: []domains.Domain{},
	}

	if err := writeConfig(&gConfig); err != nil {
		return err
	}

	fmt.Println("")
	return appendDomain(&gConfig)
}

// AddDomain appends one interactively configured domain to the live
// configuration and writes it back to config.json.
func AddDomain() error {
	current := domains.Current()
	if current == nil {
		return errors.New("no configuration loaded")
	}
	return appendDomain(current)
}

// appendDomain is the shared body: it asks for a domain, appends it to the
// given configuration and persists it. Nothing else is published - the caller
// still has to run the domain through validate and build.
func appendDomain(cfg *domains.Configuration) error {
	fmt.Println("[ " + utils.PrimaryColor("No Domain Configurations Found") + " ]")
	fmt.Println("[ " + utils.PrimaryColor("Configure New Domains In The Config.json") + " ]")
	fmt.Println("")
	gDomain := domains.Domain{
		Name:        utils.AskString("What Is The Name Of Your Domain (eg. \"example.com\")", "example.com"),
		Backend:     utils.AskString("What Is The Backed/Server The Proxy Should Proxy To?", "1.1.1.1"),
		Scheme:      strings.ToLower(utils.AskString("What Scheme Should The Proxy Use To Communicate With Your Backend? (http/https)", "http")),
		Certificate: utils.AskString("What Is The Path To The SSL Certificate For Your Domain? (Leave Empty If You Are Using The Proxy Behind Cloudflare)", ""),
		Key:         utils.AskString("What Is The Path To The SSL Key For Your Domain? (Leave Empty If You Are Using The Proxy Behind Cloudflare)", ""),
		Webhook: domains.WebhookSettings{
			URL:            utils.AskString("What Is The Url For Your Discord Webhook? (Leave Empty If You Do Not Want One)", ""),
			Name:           utils.AskString("What Is The Name For Your Discord Webhook? (Leave Empty If You Do Not Want One)", ""),
			Avatar:         utils.AskString("What Is The Url For Your Discord Webhook Avatar? (Leave Empty If You Do Not Want One)", ""),
			AttackStartMsg: utils.AskString("What Is The Message Your Webhook Should Send When Your Website Is Under Attack?", ""),
			AttackStopMsg:  utils.AskString("What Is The Message Your Webhook Should Send When Your Website Is No Longer Under Attack?", ""),
		},
		FirewallRules:       []domains.JsonRule{},
		BypassStage1:        utils.AskInt("At How Many Bypassing Requests Per Second Would You Like To Activate Stage 2?", 75),
		Stage2Difficulty:    utils.AskInt("How difficult should Stage 2 Be? (6 AT MOST recommended)", 5),
		BypassStage2:        utils.AskInt("At How Many Bypassing Requests Per Second Would You Like To Activate Stage 3?", 250),
		DisableBypassStage3: utils.AskInt("How Many Bypassing Requests Per Second Are Low Enough To Disable Stage 3?", 100),
		DisableRawStage3:    utils.AskInt("How Many Requests Per Second Are Low Enough To Disable Stage 3? (Bypassing Requests Still Have To Be Low Enough)", 250),
		DisableBypassStage2: utils.AskInt("How Many Bypassing Requests Per Second Are Low Enough To Disable Stage 2?", 50),
		DisableRawStage2:    utils.AskInt("How Many Requests Per Second Are Low Enough To Disable Stage 2? (Bypassing Requests Still Have To Be Low Enough)", 75),
	}

	cfg.Domains = append(cfg.Domains, gDomain)

	return writeConfig(cfg)
}

// writeConfig persists a configuration to ConfigPath.
func writeConfig(cfg *domains.Configuration) error {
	jsonConfig, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath, jsonConfig, 0600)
}
