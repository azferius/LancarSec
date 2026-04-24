package domains

import (
	"crypto/tls"
	"errors"
	"sync/atomic"
)

// ConfigPtr is the lock-free publisher for the live *Configuration. Readers
// use LoadConfig(); writers (config.Apply) use StoreConfig. This replaces
// direct reads of the Config global, which raced with reload.
var configPtr atomic.Pointer[Configuration]

// LoadConfig returns the currently active configuration. Never nil once the
// startup path has completed; before that it returns nil and callers should
// treat that as "not yet initialized".
func LoadConfig() *Configuration {
	return configPtr.Load()
}

// StoreConfig publishes a new configuration atomically. The old pointer is
// dropped; in-flight requests reading the previous *Configuration continue
// to operate on it safely until they return.
func StoreConfig(c *Configuration) {
	configPtr.Store(c)
	Config = c // keep the legacy global in sync for any holdouts
}

func Get(domain string) (DomainSettings, error) {
	val, ok := DomainsMap.Load(domain)
	if !ok {
		return DomainSettings{}, errors.New("domain not found")
	}
	return val.(DomainSettings), nil
}

func GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {

	domainVal, ok := DomainsMap.Load(clientHello.ServerName)
	if ok {
		tempDomain := domainVal.(DomainSettings)
		return &tempDomain.DomainCertificates, nil
	}
	return nil, nil
}
