package config

// Entry points into the configuration pipeline. The stages themselves live in
// pipeline.go; both functions below run the same ones in the same order, so
// they cannot drift apart the way Load and server.ReloadConfig did.

import (
	"errors"
	"os"
)

// Load reads config.json and publishes it, once, at startup.
//
// It returns an error instead of panicking: main reports it and exits 1. The
// old code panicked on a bad secret and then, for the one case it did not
// check - a config with zero domains - dereferenced domains.Domains[0] and
// died with a nil-index stack trace instead.
//
// Load is the only entry point allowed to prompt the operator, because it is
// the only one that runs before the terminal UI owns stdin.
func Load() error {

	cfg, err := parse(ConfigPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := Generate(); err != nil {
			return err
		}
		if cfg, err = parse(ConfigPath); err != nil {
			return err
		}
	}

	normalise(cfg)

	// A brand new config.json has no domains yet. Ask for one, then continue
	// with the file the operator just wrote - the old code recursed into Load,
	// which re-ran the fingerprint fetch and the version check (including its
	// ten second sleep) a second time and appended every domain twice.
	if len(cfg.Domains) == 0 {
		if err := appendDomain(cfg); err != nil {
			return err
		}
		normalise(cfg)
	}

	if err := validate(cfg); err != nil {
		return err
	}

	built, err := build(cfg)
	if err != nil {
		return err
	}

	publish(built, modeStartup)
	return nil
}

// Reload re-runs the pipeline against config.json while the proxy is serving.
//
// It converges the running proxy to the file: domains added, changed AND
// removed. Live mitigation state (stage, stage lock, attack flags, counters)
// survives for every domain that still exists.
//
// Any error means nothing was published and the proxy is still running the
// previous configuration, untouched. Unlike Load it never prompts and never
// makes a network call - the terminal UI owns stdin, and a `reload` must not
// block on GitHub being reachable.
func Reload() error {

	cfg, err := parse(ConfigPath)
	if err != nil {
		return err
	}

	normalise(cfg)

	if err := validate(cfg); err != nil {
		if errors.Is(err, errNoDomains) {
			// Refuse rather than tear every domain down: a config edited to
			// zero domains is almost always a mistake, and the old code
			// panicked on domains.Domains[0] here anyway.
			return errors.New("config.json defines no domains; keeping the running configuration")
		}
		return err
	}

	built, err := build(cfg)
	if err != nil {
		return err
	}

	publish(built, modeReload)
	return nil
}
