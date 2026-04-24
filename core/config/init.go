package config

// Load is the startup entrypoint. The heavy lifting lives in Apply so the
// runtime "reload" command can reuse the same code path.
func Load() {
	Apply(ModeStartup)
}

// TODO: Implement LancarSec versioning system against sec.splay.id
// Planned endpoint: https://sec.splay.id/api/version
// Expected response: { "last_version": X, "stable_version": Y, "download": "..." }
// For now this is a no-op so the proxy does not reach out to any external host.
func VersionCheck() error {
	return nil
}
