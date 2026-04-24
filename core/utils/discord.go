package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"lancarsec/core/domains"
	"lancarsec/core/pnc"
	"lancarsec/core/proxy"
	"net/http"
	"strings"
	"time"

	quickchartgo "github.com/henomis/quickchart-go"
)

func InitPlaceholders(msg string, domainData domains.DomainData, domain string) string {
	msg = strings.ReplaceAll(msg, "{{domain.name}}", domain)
	msg = strings.ReplaceAll(msg, "{{attack.start}}", domainData.RequestLogger[0].Time.Format("15:04:05"))
	msg = strings.ReplaceAll(msg, "{{attack.end}}", domainData.RequestLogger[len(domainData.RequestLogger)-1].Time.Format("15:04:05"))
	msg = strings.ReplaceAll(msg, "{{proxy.cpu}}", proxy.GetCPUUsage())
	msg = strings.ReplaceAll(msg, "{{proxy.ram}}", proxy.GetRAMUsage())

	return msg
}

// SendWebhook is the legacy entrypoint; new code should call EnqueueWebhook
// so sends go through the bounded worker pool instead of leaking goroutines
// during sustained attacks. This function now delegates to that queue.
func SendWebhook(domainData domains.DomainData, domainSettings domains.DomainSettings, notificationType int) {
	EnqueueWebhook(domainData, domainSettings, notificationType)
}

// sendWebhookSync does the actual HTTP send. Runs inside a pool worker;
// callers outside this file should use EnqueueWebhook.
func sendWebhookSync(domainData domains.DomainData, domainSettings domains.DomainSettings, notificationType int) {

	defer pnc.PanicHndl()

	if domainSettings.DomainWebhooks.URL == "" {
		return
	}

	webhookContent := Webhook{}

	switch notificationType {
	case 0:

		description := InitPlaceholders(domainSettings.DomainWebhooks.AttackStartMsg, domainData, domainSettings.Name)

		webhookContent = Webhook{
			Content:  "",
			Username: domainSettings.DomainWebhooks.Name,
			Avatar:   domainSettings.DomainWebhooks.Avatar,
			Embeds: []WebhookEmbed{
				{
					Title:       "DDoS Alert",
					Description: description,
					Color:       5814783,
					Fields: []WebhookField{
						{
							Name:  "Total requests per second",
							Value: "```\n" + fmt.Sprint(domainData.RequestsPerSecond) + "\n```",
						},
						{
							Name:  "Allowed requests per second",
							Value: "```\n" + fmt.Sprint(domainData.RequestsBypassedPerSecond) + "\n```",
						},
					},
				},
			},
		}
	case 1:

		description := InitPlaceholders(domainSettings.DomainWebhooks.AttackStopMsg, domainData, domainSettings.Name)
		requests := domainData.RequestLogger

		allowedData := ""
		totalData := ""
		CpuLoadData := ""

		for _, request := range requests {
			currTime := request.Time.Format("2006-01-02 15:04:05")
			allowedData += `{"x": "` + currTime + `", "y": ` + fmt.Sprint(request.Allowed) + `},`
			totalData += `{"x": "` + currTime + `", "y": ` + fmt.Sprint(request.Total) + ` },`
			CpuLoadData += `{"x": "` + currTime + `", "y": ` + fmt.Sprint(request.CpuUsage) + ` },`
		}

		allowedData = strings.TrimSuffix(allowedData, ",")
		totalData = strings.TrimSuffix(totalData, ",")
		CpuLoadData = strings.TrimSuffix(CpuLoadData, ",")

		chartConfig := `{
			"type": "line",
			"data": {
				"datasets": [
				{
					"fill": false,
					"spanGaps": false,
					"lineTension": 0.3,
					"data": [` + allowedData + `],
					"type": "line",
					"label": "Bypassed",
					"borderColor": "rgb(35, 159, 217)",
					"backgroundColor": "rgba(35, 159, 217, 0.5)",
					"pointRadius": 3,
					"borderWidth": 3,
					"hidden": false
				},
				{
					"fill": true,
					"spanGaps": false,
					"lineTension": 0.3,
					"data": [` + totalData + `],
					"type": "line",
					"label": "Total",
					"borderColor": "rgb(100, 100, 100)",
					"backgroundColor": getGradientFillHelper('vertical', ["rgba(100, 100, 100, 0.7)", "rgba(100, 100, 100, 0.3)", "rgba(100, 100, 100, 0.0)"]),
					"pointRadius": 3,
					"borderWidth": 3,
					"hidden": false
				},
				{
					"fill": false,
					"spanGaps": false,
					"lineTension": 0.3,
					"data": [` + CpuLoadData + `],
					"type": "line",
					"label": "CPU",
					"borderColor": "#ffffff",
					"pointRadius": 3,
					"borderWidth": 3,
					"borderDash": [
					5,
					5
					],
					"hidden": false,
					"yAxisID": "cpu"
				}
				]
			},
			"options": {
				"responsive": true,
				"legend": {
				"display": true,
				"position": "top",
				"align": "center",
				"fullWidth": true,
				"reverse": false
				},
				"scales": {
				"xAxes": [
					{
					"display": true,
					"position": "bottom",
					"type": "time",
					"distribution": "series",
					"gridLines": {
						"color": "rgba(150, 150, 150, 0.3)",
					},
					"angleLines": {
						"color": "rgba(150, 150, 150, 0.3)"
					},
					"ticks": {
						"display": true,
						"reverse": false
					}
					}
				],
				"yAxes": [
					{
					"display": true,
					"position": "left",
					"fontStyle": "bold",
					"fontSize": 20,
					"type": "linear",
					"gridLines": {
						"color": "rgba(120, 120, 120, 0.3)",
					},
					"scaleLabel": {
						"display": true,
						"labelString": "Requests",
						"fontStyle": "bold",
						"fontSize": 13
					}
					},
					{
					"id": "cpu",
					"display": true,
					"position": "right",
					"ticks": {
						"beginAtZero": true,
						"max": 100,
						"stepSize": 10
					},
					"gridLines": {
						"color": "rgba(120, 120, 120, 0.2)",
					},
					"scaleLabel": {
						"display": true,
						"labelString": "CPU Load",
						"fontStyle": "bold",
						"fontSize": 13
					}
					}
				]
				}
			}
			}
		`
		qc := quickchartgo.New()
		qc.Config = chartConfig
		qc.Width = 500
		qc.Height = 300
		qc.BackgroundColor = "#2B2D31"
		qc.Version = "2.9.4"
		chartUrl, chartErr := qc.GetShortUrl()

		if chartErr == nil {
			webhookContent = Webhook{
				Content:  "",
				Username: domainSettings.DomainWebhooks.Name,
				Avatar:   domainSettings.DomainWebhooks.Avatar,
				Embeds: []WebhookEmbed{
					{
						Title:       "DDoS Alert",
						Description: description,
						Color:       5814783,
						Fields: []WebhookField{
							{
								Name:  "Peak total requests per second",
								Value: "```\n" + fmt.Sprint(domainData.PeakRequestsPerSecond) + "\n```",
							},
							{
								Name:  "Peak allowed requests per second",
								Value: "```\n" + fmt.Sprint(domainData.PeakRequestsBypassedPerSecond) + "\n```",
							},
						},
						Image: WebhookImage{
							Url: chartUrl,
						},
					},
				},
			}
		}
	}

	webhookPayload, err := json.Marshal(webhookContent)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", domainSettings.DomainWebhooks.URL, bytes.NewBuffer(webhookPayload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// Bounded client with a hard deadline so a slow Discord endpoint can't
	// park a worker for the default 30 seconds.
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

type Webhook struct {
	Content  string         `json:"content"`
	Embeds   []WebhookEmbed `json:"embeds"`
	Username string         `json:"username"`
	Avatar   string         `json:"avatar_url"`
}

type WebhookEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []WebhookField `json:"fields"`
	Image       WebhookImage   `json:"image"`
}

type WebhookField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type WebhookImage struct {
	Url string `json:"url"`
}

type QuickchartResponse struct {
	Success string `json:"success"`
	Url     string `json:"url"`
}
