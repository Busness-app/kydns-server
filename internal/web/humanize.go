package web

import (
	"strconv"
	"time"
)

// shortDuration renders an uptime at one useful unit: an operator reads "3d 4h"
// off a tile, never "76h12m9.4s".
func shortDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h"
	}
	days := int(d.Hours()) / 24
	return strconv.Itoa(days) + "d " + strconv.Itoa(int(d.Hours())%24) + "h"
}

// sinceText renders a unix timestamp as an age. A zero stamp means the event
// has never happened, which reads as "never" rather than as a 1970 date.
func sinceText(unix int64, now time.Time) string {
	if unix == 0 {
		return "never"
	}
	d := now.Sub(time.Unix(unix, 0))
	if d < time.Second {
		return "just now"
	}
	return shortDuration(d) + " ago"
}
