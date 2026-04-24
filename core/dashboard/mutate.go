package dashboard

import (
	"encoding/json"
	"errors"
	"lancarsec/core/domains"
	"os"
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
