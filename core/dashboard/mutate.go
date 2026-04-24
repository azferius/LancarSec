package dashboard

import (
	"encoding/json"
	"errors"
	"lancarsec/core/domains"
	"os"
	"time"
)

// appendRule persists a new firewall rule into config.json for the given
// domain and writes it back to disk. Caller should follow with a
// config.Apply(ModeReload) to activate. Returns an error if the domain
// doesn't exist or the file is unwritable.
func appendRule(domain string, rule domains.JsonRule) error {
	cfg := readConfigFromDisk()
	if cfg == nil {
		return errors.New("config missing")
	}
	found := false
	for i := range cfg.Domains {
		if cfg.Domains[i].Name == domain {
			cfg.Domains[i].FirewallRules = append(cfg.Domains[i].FirewallRules, rule)
			found = true
			break
		}
	}
	if !found {
		return errors.New("domain not found in config")
	}
	return writeConfigToDisk(cfg)
}

// deleteRuleAt removes a rule at the given index for the specified domain.
// Out-of-bounds indices are rejected; persisted back to config.json.
func deleteRuleAt(domain string, index int) error {
	cfg := readConfigFromDisk()
	if cfg == nil {
		return errors.New("config missing")
	}
	for i := range cfg.Domains {
		if cfg.Domains[i].Name != domain {
			continue
		}
		rules := cfg.Domains[i].FirewallRules
		if index < 0 || index >= len(rules) {
			return errors.New("rule index out of range")
		}
		cfg.Domains[i].FirewallRules = append(rules[:index], rules[index+1:]...)
		return writeConfigToDisk(cfg)
	}
	return errors.New("domain not found in config")
}

// appendBlock persists one new block entry into the configured scope:
// scope=="global" lands on Proxy.Blocklist, otherwise the named domain's
// Blocklist slice. AddedAt is stamped now.
func appendBlock(scope string, entry domains.BlockEntry) error {
	cfg := readConfigFromDisk()
	if cfg == nil {
		return errors.New("config missing")
	}
	entry.AddedAt = time.Now().Unix()
	if scope == "global" || scope == AllDomainsSentinel {
		cfg.Proxy.Blocklist = append(cfg.Proxy.Blocklist, entry)
		return writeConfigToDisk(cfg)
	}
	for i := range cfg.Domains {
		if cfg.Domains[i].Name == scope {
			cfg.Domains[i].Blocklist = append(cfg.Domains[i].Blocklist, entry)
			return writeConfigToDisk(cfg)
		}
	}
	return errors.New("scope not found")
}

// deleteBlockAt removes a block entry by index at the given scope. Same
// scope semantics as appendBlock.
func deleteBlockAt(scope string, index int) error {
	cfg := readConfigFromDisk()
	if cfg == nil {
		return errors.New("config missing")
	}
	if scope == "global" || scope == AllDomainsSentinel {
		if index < 0 || index >= len(cfg.Proxy.Blocklist) {
			return errors.New("index out of range")
		}
		cfg.Proxy.Blocklist = append(cfg.Proxy.Blocklist[:index], cfg.Proxy.Blocklist[index+1:]...)
		return writeConfigToDisk(cfg)
	}
	for i := range cfg.Domains {
		if cfg.Domains[i].Name != scope {
			continue
		}
		list := cfg.Domains[i].Blocklist
		if index < 0 || index >= len(list) {
			return errors.New("index out of range")
		}
		cfg.Domains[i].Blocklist = append(list[:index], list[index+1:]...)
		return writeConfigToDisk(cfg)
	}
	return errors.New("scope not found")
}

// appendPathLimit persists a new PathRateLimit onto a domain. Fields not
// supplied fall back to zero values, which evaluate to sane defaults in
// firewall.compilePathLimit.
func appendPathLimit(domain string, entry domains.PathRateLimit) error {
	cfg := readConfigFromDisk()
	if cfg == nil {
		return errors.New("config missing")
	}
	for i := range cfg.Domains {
		if cfg.Domains[i].Name == domain {
			cfg.Domains[i].PathRateLimits = append(cfg.Domains[i].PathRateLimits, entry)
			return writeConfigToDisk(cfg)
		}
	}
	return errors.New("domain not found")
}

// deletePathLimitAt removes one PathRateLimit by index.
func deletePathLimitAt(domain string, index int) error {
	cfg := readConfigFromDisk()
	if cfg == nil {
		return errors.New("config missing")
	}
	for i := range cfg.Domains {
		if cfg.Domains[i].Name != domain {
			continue
		}
		list := cfg.Domains[i].PathRateLimits
		if index < 0 || index >= len(list) {
			return errors.New("index out of range")
		}
		cfg.Domains[i].PathRateLimits = append(list[:index], list[index+1:]...)
		return writeConfigToDisk(cfg)
	}
	return errors.New("domain not found")
}

// readConfigFromDisk reads config.json into a fresh struct. We don't reuse
// the in-memory domains.LoadConfig() because we're about to mutate and
// write back, and serializing a live *Configuration would also emit the
// atomic-pointer internals. Re-reading from disk gives us a clean tree.
func readConfigFromDisk() *domains.Configuration {
	data, err := os.ReadFile("config.json")
	if err != nil {
		return nil
	}
	var cfg domains.Configuration
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return &cfg
}

func writeConfigToDisk(cfg *domains.Configuration) error {
	buf, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile("config.json", buf, 0o644)
}
