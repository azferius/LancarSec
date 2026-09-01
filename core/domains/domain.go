package domains

import (
	"crypto/tls"
	"net/http/httputil"
	"sync"
	"sync/atomic"
	"time"

	"github.com/azferius/lancarsec/core/gofilter"
)

var (
	Domains     = []string{}
	DomainsMap  sync.Map
	DomainsData = map[string]DomainData{}

	// configStore holds the published configuration. It replaced the plain
	// `Config *Configuration` variable: publish used to assign that while the
	// request path read it concurrently, and every reload was a data race on
	// the one value every request starts from (CONC-02/AUTHZ-05/CRYPTO-04).
	configStore atomic.Pointer[Configuration]
)

// Current returns the last published configuration, or nil before the first
// publish. The request path reads everything config-derived through this one
// atomic load, so a reload publishes the whole set at once or not at all —
// never a new secret beside an old threshold.
func Current() *Configuration {
	return configStore.Load()
}

// Publish atomically installs c as the running configuration. The config
// pipeline calls it as the last step of publish, after every derived global
// and mirror is written, so a reader that sees the new configuration also
// sees the state published alongside it.
func Publish(c *Configuration) {
	configStore.Store(c)
}

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

	// MaxBodySize overrides Proxy.MaxBodySize for this domain. Zero means
	// "inherit"; -1 means unlimited, which is what an upload endpoint needs.
	// normalise resolves it, so by the time build reads it, it is the final
	// number and never zero.
	MaxBodySize int64 `json:"maxBodySize"`

	// PassBackendErrors forwards the backend's 5xx response body to the
	// client inside the proxy's error page. Default false: the body is
	// dropped, because it is backend-controlled content the proxy would
	// otherwise be echoing to browsers.
	PassBackendErrors bool `json:"passBackendErrors"`
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

	// MaxBodySize is the fully resolved request body ceiling in bytes for this
	// domain: never zero, and -1 for unlimited. The request path wraps
	// request.Body in http.MaxBytesReader with it.
	MaxBodySize int64
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
	Cloudflare bool `json:"cloudflare"`

	// CloudflareEnforceOrigin makes the proxy reject any request whose socket
	// peer is not a trusted proxy while Cloudflare mode is on, so an attacker
	// who has found the origin address cannot talk to it directly at all.
	//
	// It DEFAULTS TO FALSE, deliberately. Turning it on before DNS is fully
	// cut over to Cloudflare - or before the operator's own management address
	// is in TrustedProxies - locks the operator out of their own origin, and
	// the lockout is total: there is no console fallback, because the check
	// runs before any authentication. Off is the only safe default for a flag
	// whose failure mode is "the operator cannot reach the box to turn it off".
	// See core/config.normalise for where the default is applied.
	CloudflareEnforceOrigin bool `json:"cloudflare_enforce_origin"`

	// TrustedProxies is the operator-supplied list of CIDRs (a bare address is
	// accepted and canonicalised to its single-host prefix) that are merged
	// with the bundled Cloudflare ranges by trusted.Load. Only a peer inside
	// one of these ranges has its Cf-Connecting-Ip / X-Real-Ip /
	// X-Forwarded-For headers honoured as the subject IP.
	TrustedProxies []string `json:"trusted_proxies"`

	// MaxBodySize is the process-wide default request body ceiling in bytes.
	// Zero means "unset" and normalise replaces it with the built-in default;
	// -1 means unlimited. A per-domain MaxBodySize overrides it.
	MaxBodySize int64 `json:"max_body_size"`

	// BackendTLSSkipVerify disables verification of backend TLS certificates
	// when true. ABSENT DEFAULTS TO FALSE -- certificates ARE verified -- so
	// a config that predates this key keeps the secure behaviour. It applies
	// to every domain's upstream connections; see transport.Configure.
	BackendTLSSkipVerify bool `json:"backend_tls_skip_verify"`

	AdminSecret     string            `json:"adminsecret"`
	APISecret       string            `json:"apisecret"`
	Secrets         map[string]string `json:"secrets"`
	Timeout         TimeoutSettings   `json:"timeout"`
	RatelimitWindow int               `json:"ratelimit_time"`
	Ratelimits      map[string]int    `json:"ratelimits"`
	Colors          []string          `json:"colors"`
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
