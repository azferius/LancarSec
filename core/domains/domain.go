package domains

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/kor44/gofilter"
)

var (
	Domains     = []string{}
	DomainsMap  sync.Map
	DomainsData = map[string]DomainData{}
	Config      *Configuration
)

type Configuration struct {
	Proxy   Proxy    `json:"proxy"`
	Domains []Domain `json:"domains"`
}

type Domain struct {
	Name                string          `json:"name"`
	Backend             string          `json:"backend"`
	Scheme              string          `json:"scheme"`
	Certificate         string          `json:"certificate"`
	Key                 string          `json:"key"`
	Webhook             WebhookSettings `json:"webhook"`
	FirewallRules       []JsonRule      `json:"firewallRules"`
	BypassStage1        int             `json:"bypassStage1"`
	BypassStage2        int             `json:"bypassStage2"`
	Stage2Difficulty    int             `json:"stage2Difficulty"`
	DisableBypassStage3 int             `json:"disableBypassStage3"`
	DisableRawStage3    int             `json:"disableRawStage3"`
	DisableBypassStage2 int             `json:"disableBypassStage2"`
	DisableRawStage2    int             `json:"disableRawStage2"`

	// Per-domain transport knobs. All optional — zero values fall back to the
	// transport package's defaults. BackendTLSVerify=false preserves the prior
	// behavior of accepting self-signed upstream certs.
	BackendTLSVerify bool `json:"backend_tls_verify"`
	MaxIdleConns     int  `json:"max_idle_conns"`
	MaxConnsPerHost  int  `json:"max_conns_per_host"`
}

type DomainSettings struct {
	Name string

	CustomRules    []Rule
	RawCustomRules []JsonRule

	DomainProxy        *httputil.ReverseProxy
	DomainCertificates tls.Certificate
	DomainWebhooks     WebhookSettings

	BypassStage1        int
	BypassStage2        int
	DisableBypassStage3 int
	DisableRawStage3    int
	DisableBypassStage2 int
	DisableRawStage2    int
}

type DomainLog struct {
	Time      string
	IP        string
	BrowserFP string
	BotFP     string
	TLSFP     string
	Useragent string
	Path      string
}

type DomainData struct {
	Name             string
	Stage            int
	StageManuallySet bool
	Stage2Difficulty int
	RawAttack        bool
	BypassAttack     bool
	BufferCooldown   int

	LastLogs []DomainLog

	TotalRequests    int
	BypassedRequests int

	PrevRequests int
	PrevBypassed int

	RequestsPerSecond             int
	RequestsBypassedPerSecond     int
	PeakRequestsPerSecond         int
	PeakRequestsBypassedPerSecond int
	RequestLogger                 []RequestLog
}

type Proxy struct {
	Cloudflare        bool `json:"cloudflare"`
	CloudflareFullSSL bool `json:"cloudflare_full_ssl"`
	// CloudflareEnforceOrigin rejects any request in Cloudflare mode whose
	// socket peer is not in the trusted CIDR list (Cloudflare IP ranges +
	// extras). Defaults to false for backwards compat — flip to true once
	// the origin IP is not public, so attackers who discover the origin
	// cannot bypass Cloudflare. Works together with the trusted/ package.
	CloudflareEnforceOrigin bool `json:"cloudflare_enforce_origin"`
	// HideVersionHeader suppresses the `LancarSec-Proxy` response header so
	// fingerprinting attackers can't trivially read the installed version.
	// Default false keeps the header (useful for debugging); flip to true
	// in production.
	HideVersionHeader       bool              `json:"hide_version_header"`
	AdminSecret             string            `json:"adminsecret"`
	APISecret               string            `json:"apisecret"`
	Secrets                 map[string]string `json:"secrets"`
	Timeout                 TimeoutSettings   `json:"timeout"`
	RatelimitWindow         int               `json:"ratelimit_time"`
	Ratelimits              map[string]int    `json:"ratelimits"`
	Colors                  []string          `json:"colors"`
}

type TimeoutSettings struct {
	Idle       int `json:"idle"`
	Read       int `json:"read"`
	Write      int `json:"write"`
	ReadHeader int `json:"read_header"`
}

type WebhookSettings struct {
	URL            string `json:"url"`
	Name           string `json:"name"`
	Avatar         string `json:"avatar"`
	AttackStartMsg string `json:"attack_start_msg"`
	AttackStopMsg  string `json:"attack_stop_msg"`
}

type JsonRule struct {
	Expression string `json:"expression"`
	Action     string `json:"action"`
}

type Rule struct {
	Filter *gofilter.Filter
	Action string
}

type RequestLog struct {
	Time     time.Time
	Allowed  int
	Total    int
	CpuUsage string
}

type CacheResponse struct {
	Domain    string
	Timestamp int
	Status    int
	Headers   http.Header
	Body      []byte
}
