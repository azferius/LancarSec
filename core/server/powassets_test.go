package server

import (
	"html/template"
	"regexp"
	"strings"
	"testing"

	"github.com/azferius/lancarsec/global/pow"
)

// The wave-10 rebrand renamed the proxy's own asset routes from /_bProxy/ to
// /_lancarsec/ by editing Go source. It missed the copy of the crypto-js path
// that lives inside pow.min.js's worker script - a string literal inside
// minified JavaScript, invisible to every grep the rebrand ran. The worker
// then called importScripts on a path nothing served, threw, and reported no
// solution, so stage 2 was unsolvable for every challenged visitor.
//
// This test reads the embedded assets the way the browser does: any proxy path
// they name must be a path the middleware actually serves.
func TestPowAssetsReferenceOnlyServedPaths(t *testing.T) {
	served := map[string]bool{
		powAssetPath:    true,
		powCryptoJSPath: true,
	}

	// Both the current and the pre-rebrand prefix, so a half-done rename is
	// caught rather than passing because only the new spelling was searched.
	proxyPath := regexp.MustCompile(`/(?:_lancarsec|_bProxy)/[A-Za-z0-9._-]+`)

	for name, asset := range map[string][]byte{
		"pow.min.js":       pow.BalooPow,
		"crypto-js.min.js": pow.CryptoJS,
	} {
		for _, path := range proxyPath.FindAllString(string(asset), -1) {
			if !served[path] {
				t.Errorf("%s references %q, which the middleware does not serve; served paths are %q and %q",
					name, path, powAssetPath, powCryptoJSPath)
			}
		}
	}
}

// The stage-2 worker must import crypto-js from the proxy's own origin. If
// this ever points at a CDN again, every challenged visitor's IP leaks to a
// third party and a CDN outage kills stage 2 mid-attack.
func TestPowWorkerImportsCryptoJSFirstParty(t *testing.T) {
	src := string(pow.BalooPow)
	// The worker body is itself a JS string literal inside the minified
	// bundle, so its quotes are backslash-escaped in the file.
	want := `importScripts(self.location.origin+\'` + powCryptoJSPath + `\')`
	if !strings.Contains(src, want) {
		t.Errorf("pow.min.js does not contain %q", want)
	}
	if strings.Contains(src, "cdnjs.cloudflare.com") || strings.Contains(src, "cdn.jsdelivr.net") {
		t.Error("pow.min.js reaches a third-party CDN at challenge time")
	}
}

// The stage-2 page shipped upstream's own Discord handle in its failure
// branch, so a visitor whose challenge failed on this fork was told to contact
// a stranger. It also called alert() with e.match on a null result: when the
// solver found nothing - which is exactly what happened while the worker's
// crypto-js import was broken - reading .match on null threw, the handler died
// silently, and the page sat on its loader forever with no message and no
// retry.
func TestStage2PageFailurePath(t *testing.T) {
	var rendered strings.Builder
	if err := stage2Page.Execute(&rendered, stage2PageData{
		CookieName:   "_2__lSec_v",
		PublicSalt:   "salt",
		Challenge:    "challenge",
		Difficulty:   template.JS("4"),
		BalooPowPath: powAssetPath,
		CryptoJSPath: powCryptoJSPath,
	}); err != nil {
		t.Fatalf("stage2Page.Execute: %v", err)
	}
	page := rendered.String()

	for _, leak := range []string{"@ddosmitigation", "41Baloo", "baloo.dog"} {
		if strings.Contains(page, leak) {
			t.Errorf("stage-2 page contains upstream contact %q; a challenged visitor must not be sent to a stranger", leak)
		}
	}
	if strings.Contains(page, "alert(") {
		t.Error("stage-2 page reports failure with alert(); it must render into the page instead")
	}
	// A null or unsolved result must reload rather than throw.
	if !strings.Contains(page, "location.reload()") {
		t.Error("stage-2 page has no retry path for an unsolved challenge")
	}
	if !strings.Contains(page, ".catch(") {
		t.Error("stage-2 solve has no catch; a throwing solver leaves the visitor on the loader forever")
	}
}
