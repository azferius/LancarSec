package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"lancarsec/core/domains"
	"lancarsec/core/firewall"
	"lancarsec/core/proxy"
	"lancarsec/core/utils"
	"net/http"
	"strings"
)

// secretsEqual does a constant-time compare so the API/admin secret cannot be
// probed byte-by-byte by timing the 401 response.
func secretsEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func Process(writer http.ResponseWriter, request *http.Request, domainData domains.DomainData) bool {

	if !secretsEqual(request.Header.Get("proxy-secret"), proxy.APISecret) {
		return false
	}

	reqBody, err := io.ReadAll(request.Body)
	if err != nil {
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_BODY_READ_FAILED,
		})
	}

	defer request.Body.Close()

	var apiRequest API_REQUEST
	err = json.Unmarshal(reqBody, &apiRequest)
	if err != nil {
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_JSON_READ_FAILED,
		})
		return true
	}

	if apiRequest.Domain == "" {
		handleProxyActions(apiRequest.Action, writer)
		return true
	}

	uncastedDomainSettings, ok := domains.DomainsMap.Load(apiRequest.Domain)
	if !ok {
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_DOMAIN_NOT_FOUND,
		})
		return true
	}
	domainSettings, _ := uncastedDomainSettings.(domains.DomainSettings)

	handleDomainActions(apiRequest.Action, writer, &domainData, &domainSettings)
	return true
}

func handleProxyActions(action string, writer http.ResponseWriter) {
	switch action {
	case "GET_PROXY_STATS":
		APIResponse(writer, true, map[string]interface{}{
			"CPU_USAGE": proxy.CpuUsage,
			"RAM_USAGE": proxy.RamUsage,
		})
	case "GET_PROXY_STATS_CPU_USAGE":
		APIResponse(writer, true, map[string]interface{}{
			"CPU_USAGE": proxy.CpuUsage,
		})
	case "GET_PROXY_STATS_RAM_USAGE":
		APIResponse(writer, true, map[string]interface{}{
			"RAM_USAGE": proxy.RamUsage,
		})
	case "GET_IP_REQUESTS":
		firewall.CountersMu.RLock()
		ipsAll := firewall.AccessIps
		ipsCookie := firewall.AccessIpsCookie
		firewall.CountersMu.RUnlock()

		APIResponse(writer, true, map[string]interface{}{
			"TOTAL_IP_REQUESTS":     ipsAll,
			"CHALLENGE_IP_REQUESTS": ipsCookie,
		})
	//Only returns UNK Fingerprints
	case "GET_FINGERPRINT_REQUESTS":
		firewall.CountersMu.RLock()
		ipsFps := firewall.UnkFps
		firewall.CountersMu.RUnlock()

		APIResponse(writer, true, map[string]interface{}{
			"TOTAL_FINGERPRINT_REQUESTS": ipsFps,
		})
	case "GET_IP_CACHE":
		cacheIps := make(map[string]interface{})
		firewall.CacheIps.Range(func(key, value any) bool {
			cacheIps[fmt.Sprint(key)] = value
			return true
		})

		APIResponse(writer, true, map[string]interface{}{
			"IP_CACHE": cacheIps,
		})
	// Useful to fill up your ipCache and see how your proxy performs with high memory usage
	case "FILL_IP_CACHE":
		// CacheIps is a sync.Map, so concurrent Store is safe without a lock.
		for i := 0; i < 19980; i++ {
			firewall.CacheIps.Store(utils.RandomString(24), utils.RandomString(64))
		}

		APIResponse(writer, true, map[string]interface{}{})
	case "RELOAD":
		// No-op placeholder; a real reload should call config.Apply via the
		// reload command.
	default:
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_ACTION_NOT_FOUND,
		})
	}
}

func handleDomainActions(action string, writer http.ResponseWriter, domainData *domains.DomainData, domainSettings *domains.DomainSettings) {
	switch action {
	case "GET_TOTAL_REQUESTS":
		APIResponse(writer, true, map[string]interface{}{
			"TOTAL_REQUESTS": domainData.TotalRequests,
		})
	case "GET_BYPASSED_REQUESTS":
		APIResponse(writer, true, map[string]interface{}{
			"BYPASSED_REQUESTS": domainData.BypassedRequests,
		})
	case "GET_TOTAL_REQUESTS_PER_SECOND":
		APIResponse(writer, true, map[string]interface{}{
			"TOTAL_REQUESTS_REQUESTS_PER_SECOND": domainData.RequestsPerSecond,
		})
	case "GET_BYPASSED_REQUESTS_PER_SECOND":
		APIResponse(writer, true, map[string]interface{}{
			"BYPASSED_REQUESTS_REQUESTS_PER_SECOND": domainData.RequestsBypassedPerSecond,
		})
	case "GET_FIREWALL_RULES":
		APIResponse(writer, true, map[string]interface{}{
			"FIREWALL_RULES": domainSettings.RawCustomRules,
		})
	case "GET_LOGS":
		APIResponse(writer, true, map[string]interface{}{
			"LOGS": domainData.LastLogs,
		})
	default:
		APIResponse(writer, false, map[string]interface{}{
			"ERROR": ERR_ACTION_NOT_FOUND,
		})
	}
}

func ProcessV2(w http.ResponseWriter, r *http.Request) bool {

	if !secretsEqual(r.Header.Get("Proxy-Secret"), proxy.APISecret) {
		return false
	}

	path := strings.TrimPrefix(r.URL.Path, "/_lancarsec/api/v2/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || (len(parts) == 1 && parts[0] == "") {
		return false
	}

	if len(parts) == 1 {

		// /:action

		handleProxyActions(parts[0], w)
		return true
	} else {

		//  /:domain/:action

		uncastedDomainSettingsdomain, ok := domains.DomainsMap.Load(parts[0])
		if !ok {
			APIResponse(w, false, map[string]interface{}{
				"ERROR": ERR_DOMAIN_NOT_FOUND,
			})
			return true
		}
		domainSettingsdomain, _ := uncastedDomainSettingsdomain.(domains.DomainSettings)

		firewall.DataMu.RLock()
		domainData := domains.DomainsData[parts[0]]
		firewall.DataMu.RUnlock()

		handleDomainActions(parts[1], w, &domainData, &domainSettingsdomain)
		return true
	}
}

func APIResponse(writer http.ResponseWriter, success bool, response map[string]interface{}) error {

	writer.Header().Set("Content-Type", "application/json")

	apiResponse := API_RESPONSE{
		Success:  success,
		Response: response,
	}

	jsonResponse, err := json.Marshal(apiResponse)
	if err != nil {
		return err
	}

	fmt.Fprint(writer, string(jsonResponse))
	return nil
}
