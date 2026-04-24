package server

import (
	"strconv"
	"strings"
)

// Shared style block for both challenge pages. Inline CSS (no external fetch)
// so the page renders instantly even on a fresh unchallenged visitor.
const challengeStyles = `
*,*::before,*::after{box-sizing:border-box}
body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
 background:radial-gradient(1200px 600px at 50% -10%,#1e293b 0%,#0f172a 60%,#020617 100%);
 color:#e2e8f0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:480px;background:rgba(15,23,42,.72);backdrop-filter:blur(20px) saturate(150%);
 -webkit-backdrop-filter:blur(20px) saturate(150%);border:1px solid rgba(148,163,184,.15);
 border-radius:16px;padding:40px 32px;box-shadow:0 20px 60px -20px rgba(0,0,0,.6),0 0 0 1px rgba(255,255,255,.05) inset}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:28px;color:#94a3b8;font-size:13px;font-weight:500;letter-spacing:.02em}
.brand-dot{width:8px;height:8px;border-radius:50%;background:linear-gradient(135deg,#06b6d4,#3b82f6);box-shadow:0 0 12px rgba(59,130,246,.6)}
h1{margin:0 0 8px;font-size:20px;font-weight:600;color:#f8fafc;letter-spacing:-.01em}
p.lead{margin:0 0 28px;font-size:14px;line-height:1.55;color:#94a3b8}
.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;
 background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.25);color:#93c5fd;font-size:11px;
 font-weight:500;letter-spacing:.02em;margin-bottom:20px}
.progress{height:4px;background:rgba(148,163,184,.1);border-radius:999px;overflow:hidden;margin:24px 0 16px;position:relative}
.progress-bar{height:100%;width:40%;background:linear-gradient(90deg,#06b6d4,#3b82f6,#8b5cf6);
 border-radius:999px;animation:indeterminate 1.8s ease-in-out infinite}
@keyframes indeterminate{0%{margin-left:-40%}100%{margin-left:100%}}
.status{font-size:13px;color:#cbd5e1;text-align:left;display:flex;align-items:center;gap:10px}
.status-dot{width:6px;height:6px;border-radius:50%;background:#3b82f6;animation:pulse 1.5s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.5}50%{opacity:1}}
.success{background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.35);color:#6ee7b7;padding:14px 16px;border-radius:10px;font-size:13px;display:none}
.failure{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:#fca5a5;padding:14px 16px;border-radius:10px;font-size:13px;display:none}
.footer{margin-top:28px;padding-top:20px;border-top:1px solid rgba(148,163,184,.1);
 display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#64748b}
.footer a{color:#94a3b8;text-decoration:none}
.footer a:hover{color:#cbd5e1}
.meta{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:11px;color:#64748b;word-break:break-all}
.details{margin-top:20px;font-size:12px;color:#64748b}
.details-toggle{background:none;border:none;color:#94a3b8;cursor:pointer;padding:0;font-size:12px;text-decoration:underline;text-underline-offset:3px}
.details-body{max-height:0;overflow:hidden;transition:max-height .25s ease-out;color:#94a3b8;line-height:1.5}
.details-body.open{max-height:200px;padding-top:10px}
input[type=text]{width:100%;padding:12px 14px;margin:10px 0;background:rgba(15,23,42,.6);
 border:1px solid rgba(148,163,184,.25);border-radius:8px;color:#f8fafc;font-size:14px;
 font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.1em;text-align:center;transition:border-color .15s}
input[type=text]:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15)}
input[type=range]{-webkit-appearance:none;appearance:none;width:100%;height:6px;background:rgba(148,163,184,.15);
 border-radius:999px;outline:none;margin:14px 0}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;appearance:none;width:20px;height:20px;
 background:linear-gradient(135deg,#06b6d4,#3b82f6);border-radius:50%;cursor:grab;
 box-shadow:0 2px 8px rgba(59,130,246,.4),0 0 0 1px rgba(255,255,255,.1) inset}
input[type=range]::-webkit-slider-thumb:active{cursor:grabbing}
input[type=range]::-moz-range-thumb{width:20px;height:20px;background:linear-gradient(135deg,#06b6d4,#3b82f6);
 border-radius:50%;cursor:grab;border:none;box-shadow:0 2px 8px rgba(59,130,246,.4)}
button.primary{width:100%;padding:12px 16px;background:linear-gradient(135deg,#3b82f6,#2563eb);
 color:white;border:none;border-radius:8px;font-weight:500;font-size:14px;cursor:pointer;
 transition:transform .1s,box-shadow .15s;margin-top:8px}
button.primary:hover{box-shadow:0 4px 16px rgba(59,130,246,.35)}
button.primary:active{transform:translateY(1px)}
.captcha-wrapper{position:relative;width:100%;aspect-ratio:100/37;margin:16px 0;
 background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.15);border-radius:8px;overflow:hidden}
.captcha-wrapper canvas{position:absolute;top:0;left:0;width:100%;height:100%;image-rendering:pixelated}
.hint{font-size:12px;color:#94a3b8;text-align:center;margin:12px 0 4px}
`

// challengeFooter is the branded footer shown on every challenge page.
// "Security by LancarSec" — consistent with product positioning.
const challengeFooter = `<div class=footer><span>Security by <a href="https://sec.splay.id" target=_blank rel=noopener><strong>LancarSec</strong></a></span><span class=meta id=reqid></span></div>`

// renderJSChallenge builds the Stage 2 (JS proof-of-work) HTML. LancarPow
// solves the puzzle in a web worker pool; on success the page sets the
// challenge cookie and reloads.
func renderJSChallenge(publicSalt, hashedEncryptedIP string, difficulty int) string {
	var b strings.Builder
	b.Grow(4096)
	b.WriteString(`<!doctype html><html lang=en><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><meta name=robots content="noindex,nofollow"><title>Verifying your connection…</title>`)
	b.WriteString(`<style>`)
	b.WriteString(challengeStyles)
	b.WriteString(`</style></head><body><main class=card>`)
	b.WriteString(`<div class=brand><span class=brand-dot></span><span>LANCARSEC · DDoS PROTECTION</span></div>`)
	b.WriteString(`<div class=pill>Checking your browser</div>`)
	b.WriteString(`<h1>One moment, verifying your connection</h1>`)
	b.WriteString(`<p class=lead>We're running an automated security check. This usually takes a few seconds and requires no action from you.</p>`)
	b.WriteString(`<div class=progress><div class=progress-bar></div></div>`)
	b.WriteString(`<div class=status><span class=status-dot></span><span id=stat>Computing proof of work…</span></div>`)
	b.WriteString(`<div class=details><button class=details-toggle type=button onclick="document.getElementById('d').classList.toggle('open')">Why am I seeing this?</button><div id=d class=details-body><p>The site you're visiting uses LancarSec to shield itself from abuse. Your browser is completing a short computational challenge that is easy for real users and costly for automated bots. No data is sent other than the solution itself.</p></div></div>`)
	b.WriteString(challengeFooter)
	b.WriteString(`</main>`)
	b.WriteString(`<script src="/_lancarsec/static/lancarpow.min.js"></script>`)
	b.WriteString(`<script src="/_lancarsec/static/crypto-js.min.js"></script>`)
	b.WriteString(`<script>
(function(){
  var publicSalt=` + jsString(publicSalt) + `;
  var challenge=` + jsString(hashedEncryptedIP) + `;
  var difficulty=` + strconv.Itoa(difficulty) + `;
  document.getElementById('reqid').textContent=publicSalt.slice(0,8);
  function solved(e){
    document.cookie="_2__lSec_v="+publicSalt+e.solution+"; SameSite=Lax; Path=/; Secure";
    document.getElementById('stat').textContent='Verified. Redirecting…';
    setTimeout(function(){location.href=location.href;},450);
  }
  new LancarPow(publicSalt,difficulty,challenge,!1).Solve().then(function(e){
    if(!e){document.getElementById('stat').textContent='Verification failed. Retrying…';setTimeout(function(){location.href=location.href;},1500);return;}
    if(e.match===""){solved(e);}
    else{document.getElementById('stat').textContent='Browser mismatch ('+e.match+'). Contact the site administrator.';}
  });
})();
</script></body></html>`)
	return b.String()
}

// renderCaptchaChallenge builds the Stage 3 (visual captcha) HTML. User types
// the green letters they see and drags the slider so the overlay mask reveals
// them. On submit the answer becomes a cookie; server validates.
func renderCaptchaChallenge(ip, publicPart, captchaData, maskData string) string {
	var b strings.Builder
	b.Grow(5120)
	b.WriteString(`<!doctype html><html lang=en><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><meta name=robots content="noindex,nofollow"><title>Confirm you're human</title>`)
	b.WriteString(`<style>`)
	b.WriteString(challengeStyles)
	b.WriteString(`</style></head><body><main class=card>`)
	b.WriteString(`<div class=brand><span class=brand-dot></span><span>LANCARSEC · CAPTCHA</span></div>`)
	b.WriteString(`<div class=pill>Human verification</div>`)
	b.WriteString(`<h1>Drag the slider, then type what you see</h1>`)
	b.WriteString(`<p class=lead>Move the slider below to reveal the <strong style="color:#6ee7b7">green</strong> letters on the image. Type the six characters exactly.</p>`)
	b.WriteString(`<div class=captcha-wrapper><canvas id=captcha width=100 height=37></canvas><canvas id=mask width=100 height=37></canvas></div>`)
	b.WriteString(`<input id=slider type=range min=-50 max=50 value=0>`)
	b.WriteString(`<form onsubmit="return checkAnswer(event)" autocomplete=off>`)
	b.WriteString(`<input id=text type=text maxlength=6 placeholder="6 characters" required spellcheck=false autocapitalize=off autocomplete=off>`)
	b.WriteString(`<button type=submit class=primary>Submit</button>`)
	b.WriteString(`</form>`)
	b.WriteString(`<div class=success id=successMessage>✓ Verified. Redirecting…</div>`)
	b.WriteString(`<div class=failure id=failMessage>✗ That doesn't match. Please try again.</div>`)
	b.WriteString(`<div class=details><button class=details-toggle type=button onclick="document.getElementById('d').classList.toggle('open')">Why am I seeing this?</button><div id=d class=details-body><p>The site is currently under elevated protection. Completing this one-time check tells LancarSec that you're not an automated client. Your response is used only for this verification.</p></div></div>`)
	b.WriteString(challengeFooter)
	b.WriteString(`</main>`)
	b.WriteString(`<script>
(function(){
  var ip=` + jsString(ip) + `;
  var publicPart=` + jsString(publicPart) + `;
  var captchaImg=new Image();
  var maskImg=new Image();
  var cc=document.getElementById('captcha').getContext('2d');
  var mc=document.getElementById('mask').getContext('2d');
  var slider=document.getElementById('slider');
  document.getElementById('reqid').textContent=publicPart.slice(0,8);
  captchaImg.onload=function(){cc.drawImage(captchaImg,0,0);};
  captchaImg.src='data:image/png;base64,` + captchaData + `';
  maskImg.onload=function(){mc.drawImage(maskImg,0,0);};
  maskImg.src='data:image/png;base64,` + maskData + `';
  function updateMask(){
    var off=parseInt(slider.value,10);
    mc.clearRect(0,0,100,37);
    mc.drawImage(maskImg,off,0);
  }
  slider.oninput=updateMask;
  window.checkAnswer=function(e){
    e.preventDefault();
    var v=document.getElementById('text').value;
    document.cookie=ip+"_3__lSec_v="+v+publicPart+"; SameSite=Lax; Path=/; Secure";
    fetch("https://"+location.hostname+"/_lancarsec/verified").then(function(r){return r.text();}).then(function(t){
      if(t==="verified"){
        document.getElementById('successMessage').style.display='block';
        setTimeout(function(){location.href=location.href;},600);
      } else {
        document.getElementById('failMessage').style.display='block';
        setTimeout(function(){location.href=location.href;},1200);
      }
    }).catch(function(){
      document.getElementById('failMessage').style.display='block';
      setTimeout(function(){location.href=location.href;},1200);
    });
    return false;
  };
})();
</script></body></html>`)
	return b.String()
}

// jsString safely embeds a Go string as a JS string literal. Quotes internal
// double-quotes and backslashes; the input is always generated server-side
// (hash hex / IP / salt) so it contains only ASCII alphanumerics in practice,
// but escaping keeps this defensive against future callers.
func jsString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '<':
			// Prevent </script> injection breaking out of the script block.
			b.WriteString(`<`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
