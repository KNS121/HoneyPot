package rules

import "time"

func CleanupOldAlerts(alerts map[string]time.Time, now time.Time, cooldown time.Duration) {
	for key, alertTime := range alerts {
		if now.Sub(alertTime) > cooldown {
			delete(alerts, key)
		}
	}
}