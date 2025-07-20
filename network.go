package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

func checkPort(host string, portInfo PortInfo, ch chan<- PortStatus, wg *sync.WaitGroup) {
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

	} else {
		portStatus.IsOpen = true
		conn.Close()
	}

	ch <- portStatus
}

func scanPorts(host string) []PortStatus {
	start := time.Now()

	var wg sync.WaitGroup

	var ports []PortInfo
	ch := make(chan PortStatus)
	ports = append(ports, CriticalPorts...)
	ports = append(ports, CommonPorts...)
	ports = append(ports, OptionalPorts...)

	var results []PortStatus
	go func() {
		wg.Wait()
		close(ch)
	}()

	for _, port := range ports {
		wg.Add(1)
		go checkPort(host, port, ch, &wg)
	}

	for portStatus := range ch {
		results = append(results, portStatus)
	}

	duration := time.Since(start)
	fmt.Printf("Port scan completed in %v\n", duration)

	return results
}

func displayPortResults(results []PortStatus) {
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
		fmt.Printf("\n🔓 OPEN PORTS (%d found):\n", len(openPorts))
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
		fmt.Printf("\n🔒 CLOSED PORTS: %d ports tested but closed\n", len(closedPorts))
	}

}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
