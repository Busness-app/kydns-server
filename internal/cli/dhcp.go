package cli

import (
	"fmt"
	"io"
)

const dhcpUsage = `usage:
  kydns dhcp status
  kydns dhcp leases`

func dhcpCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, dhcpUsage)
		return 2
	}
	switch args[0] {
	case "status":
		st, err := dhcpStatus(c)
		if err != nil {
			return fail(stderr, err)
		}
		printDHCPStatus(st, stdout)
		return 0
	case "leases":
		return dhcpLeases(c, stdout, stderr)
	}
	fmt.Fprintf(stderr, "kydns: unknown dhcp subcommand %q\n", args[0])
	return 2
}

// dhcpState is GET /api/v1/dhcp/status. The error is carried separately from
// running: a server that is off and one that refused to start both serve no
// leases, and only the second has something to fix.
type dhcpState struct {
	Running bool   `json:"running"`
	Error   string `json:"error"`
}

func dhcpStatus(c *Client) (dhcpState, error) {
	var st dhcpState
	err := c.Do("GET", "/api/v1/dhcp/status", nil, &st)
	return st, err
}

func printDHCPStatus(st dhcpState, stdout io.Writer) {
	running := "no"
	if st.Running {
		running = "yes"
	}
	fmt.Fprintf(stdout, "running      %s\n", running)
	if st.Error != "" {
		fmt.Fprintf(stdout, "last error   %s\n", st.Error)
	}
}

// dhcpLeases reads the one lease listing there is: the built-in server's
// leases reach it through the same poller a lease file does.
func dhcpLeases(c *Client, stdout, stderr io.Writer) int {
	var out struct {
		Leases []struct {
			Hostname string `json:"hostname"`
			Address  string `json:"address"`
			MAC      string `json:"mac"`
			Expires  int64  `json:"expires"`
		} `json:"leases"`
	}
	if err := c.Do("GET", "/api/v1/leases", nil, &out); err != nil {
		return fail(stderr, err)
	}
	if len(out.Leases) == 0 {
		// An empty table cannot say whether anything is serving. An operator
		// who just turned DHCP on needs the reason, not a blank.
		st, err := dhcpStatus(c)
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintln(stdout, "no leases")
		if !st.Running {
			fmt.Fprintln(stdout, "the built-in DHCP server is not running")
		}
		if st.Error != "" {
			fmt.Fprintf(stdout, "  %s\n", st.Error)
		}
		return 0
	}
	for _, l := range out.Leases {
		fmt.Fprintf(stdout, "%-18s %-24s %-18s %s\n",
			l.Address, l.Hostname, l.MAC, unixTime(l.Expires))
	}
	return 0
}
