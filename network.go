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

func scanPorts(host string) PortStatus {
	start := time.Now()

	var wg sync.WaitGroup

	var ports []PortInfo
	ch := make(chan []PortStatus)
	ports = append(ports, CriticalPorts...)
	ports = append(ports, CommonPorts...)
	ports = append(ports, OptionalPorts...)

	for _, port := range ports {
		wg.Add(1)
		go checkPort(host, port, port.Protocol, &wg)
	}
	wg.Wait()
	duration := time.Since(start)
	fmt.Printf("Port scan completed in %v\n", duration)

	return PortStatus{}
}
