package utils

import (
	"lancarsec/core/domains"
	"lancarsec/core/pnc"
)

// webhookJob carries one pending webhook send through the worker pool.
type webhookJob struct {
	data             domains.DomainData
	settings         domains.DomainSettings
	notificationType int
}

// webhookQueue is a bounded channel feeding a small pool of sender workers.
// Capacity keeps attacker-triggered stage transitions from spawning an
// unbounded goroutine tail during a sustained attack.
var webhookQueue = make(chan webhookJob, 256)

func init() {
	// 4 workers is plenty: Discord rate limits webhooks anyway, and having
	// more workers mostly means more 429 retries.
	for i := 0; i < 4; i++ {
		go webhookWorker()
	}
}

func webhookWorker() {
	defer pnc.PanicHndl()
	for job := range webhookQueue {
		sendWebhookSync(job.data, job.settings, job.notificationType)
	}
}

// EnqueueWebhook replaces the old `go SendWebhook(...)` call pattern. Bounded
// and non-blocking: if the queue is full (backlog already high), new alerts
// are dropped instead of compounding the goroutine count. The proxy's job is
// to stay alive under attack, not to guarantee every Discord ping is sent.
func EnqueueWebhook(data domains.DomainData, settings domains.DomainSettings, notificationType int) {
	select {
	case webhookQueue <- webhookJob{data, settings, notificationType}:
	default:
		// Queue full — drop. The next stage transition will enqueue another.
	}
}
