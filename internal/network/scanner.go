package network

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gaetangr/synaudit/internal/api"
	"github.com/gaetangr/synaudit/internal/audit"
)

func ScanPorts(host string) ([]PortStatus, []api.Finding) {
	start := time.Now()

	var wg sync.WaitGroup

	var ports []PortInfo
	ch := make(chan PortStatus)
	ports = append(ports, CriticalPorts...)
	ports = append(ports, CommonPorts...)
	ports = append(ports, OptionalPorts...)

	var results []PortStatus
	var findings []api.Finding

	go func() {
		wg.Wait()
		close(ch)
	}()

	for _, port := range ports {
		wg.Add(1)
		go scanPort(host, port, ch, &wg)
	}

	for portStatus := range ch {
		results = append(results, portStatus)

		if portStatus.IsOpen {
			switch portStatus.Port {
			case 22:
				findings = append(findings, audit.SecurityFindings["SSH_DEFAULT_PORT"])
			case 23:
				findings = append(findings, audit.SecurityFindings["TELNET_ENABLED"])
			case 21:
				findings = append(findings, audit.SecurityFindings["FTP_ENABLED"])
			case 445:
				findings = append(findings, api.Finding{
					Title:       "SMB service exposed",
					Description: "SMB file sharing is accessible from the network",
					Remediation: "Ensure SMB is properly secured and only accessible to trusted networks",
				})
			}
		}
	}

	duration := time.Since(start)
	fmt.Printf("Port scan completed in %v\n", duration)

	return results, findings
}

func scanPort(host string, portInfo PortInfo, ch chan<- PortStatus, wg *sync.WaitGroup) {
	defer wg.Done()

	address := net.JoinHostPort(host, fmt.Sprintf("%d", portInfo.Port))
	conn, err := net.DialTimeout(portInfo.Protocol, address, 900*time.Millisecond)

	portStatus := PortStatus{
		Port:        portInfo.Port,
		Service:     portInfo.Service,
		Description: portInfo.Description,
		IsOpen:      false,
	}

	if err != nil {
		// Port is closed or filtered
	} else {
		portStatus.IsOpen = true
		conn.Close()
	}

	ch <- portStatus
}

func DisplayPortResults(results []PortStatus) {
	if len(results) == 0 {
		fmt.Println("No ports scanned.")
		return
	}

	var openPorts []PortStatus
	var closedPorts []PortStatus

	for _, port := range results {
		if port.IsOpen {
			openPorts = append(openPorts, port)
		} else {
			closedPorts = append(closedPorts, port)
		}
	}

	if len(openPorts) > 0 {
		fmt.Printf("\nOPEN PORTS (%d found):\n", len(openPorts))
		fmt.Println("┌──────┬─────────────────────┬──────────┬─────────────────────────────────────────────────────┐")
		fmt.Println("│ Port │ Service             │ Status   │ Description                                         │")
		fmt.Println("├──────┼─────────────────────┼──────────┼─────────────────────────────────────────────────────┤")

		for _, port := range openPorts {
			fmt.Printf("│ %-4d │ %-19s │ %-8s │ %-51s │\n",
				port.Port,
				truncateString(port.Service, 19),
				"OPEN",
				truncateString(port.Description, 51))
		}
		fmt.Println("└──────┴─────────────────────┴──────────┴─────────────────────────────────────────────────────┘")
	}

	if len(closedPorts) > 0 {
		fmt.Printf("\nCLOSED PORTS: %d ports tested but closed\n", len(closedPorts))
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
