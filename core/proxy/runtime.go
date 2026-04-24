package proxy

import (
	"sync/atomic"
	"time"
)

var (
	cpuUsageValue            atomic.Value
	ramUsageValue            atomic.Value
	cookieOTPValue           atomic.Value
	jsOTPValue               atomic.Value
	captchaOTPValue          atomic.Value
	currHourStringValue      atomic.Value
	lastSecondFormattedValue atomic.Value
	watchedDomainValue       atomic.Value

	lastSecondTimestampValue   atomic.Int64
	last10SecondTimestampValue atomic.Int64
	initialisedValue           atomic.Bool
)

func init() {
	cpuUsageValue.Store("")
	ramUsageValue.Store("")
	cookieOTPValue.Store("")
	jsOTPValue.Store("")
	captchaOTPValue.Store("")
	currHourStringValue.Store("")
	lastSecondFormattedValue.Store("")
	watchedDomainValue.Store("")
}

func SetCPUUsage(value string) {
	cpuUsageValue.Store(value)
	CpuUsage = value
}

func GetCPUUsage() string {
	return cpuUsageValue.Load().(string)
}

func SetRAMUsage(value string) {
	ramUsageValue.Store(value)
	RamUsage = value
}

func GetRAMUsage() string {
	return ramUsageValue.Load().(string)
}

func SetOTP(cookie, js, captcha string) {
	cookieOTPValue.Store(cookie)
	jsOTPValue.Store(js)
	captchaOTPValue.Store(captcha)
	CookieOTP = cookie
	JSOTP = js
	CaptchaOTP = captcha
}

func GetCookieOTP() string {
	return cookieOTPValue.Load().(string)
}

func GetJSOTP() string {
	return jsOTPValue.Load().(string)
}

func GetCaptchaOTP() string {
	return captchaOTPValue.Load().(string)
}

func SetRuntimeClock(now time.Time) {
	formatted := now.Format("15:04:05")
	hour, _, _ := now.Clock()
	hourString := itoa(hour)
	sec := int64(now.Unix())
	trimmed := (sec / 10) * 10

	lastSecondFormattedValue.Store(formatted)
	currHourStringValue.Store(hourString)
	lastSecondTimestampValue.Store(sec)
	last10SecondTimestampValue.Store(trimmed)

	LastSecondTime = now
	LastSecondTimeFormated = formatted
	LastSecondTimestamp = int(sec)
	Last10SecondTimestamp = int(trimmed)
	CurrHour = hour
	CurrHourStr = hourString
}

func GetLastSecondFormatted() string {
	return lastSecondFormattedValue.Load().(string)
}

func GetLastSecondTimestamp() int {
	return int(lastSecondTimestampValue.Load())
}

func GetLast10SecondTimestamp() int {
	return int(last10SecondTimestampValue.Load())
}

func GetCurrHourStr() string {
	return currHourStringValue.Load().(string)
}

func SetWatchedDomain(domain string) {
	watchedDomainValue.Store(domain)
	WatchedDomain = domain
}

func GetWatchedDomain() string {
	return watchedDomainValue.Load().(string)
}

func SetInitialised(value bool) {
	initialisedValue.Store(value)
	Initialised = value
}

func IsInitialised() bool {
	return initialisedValue.Load()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
