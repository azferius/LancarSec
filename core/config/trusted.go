package config

import "github.com/azferius/lancarsec/core/trusted"

// The trusted-proxy set: where the pipeline hands off to core/trusted.
//
// loadTrusted installs the trusted-proxy set. It is called from publish, once,
// with the operator-supplied CIDR list; core/trusted merges the bundled
// Cloudflare ranges itself and returns the total prefix count.
//
// It is a variable so the pipeline tests can stub it, count calls and prove
// that a configuration refused by validate never reaches the install.
// Production never reassigns it.
var loadTrusted = trusted.Load
