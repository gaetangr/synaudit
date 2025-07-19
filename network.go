package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

func checkPort(host string, port int, protocol string, wg *sync.WaitGroup) bool {
	defer wg.Done()

	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout(protocol, address, 900*time.Millisecond)
	if err != nil {
		fmt.Printf("Failed to connect to %s: %v\n", address, err)
		return false
	}
	fmt.Printf("Successfully connected to %s\n", conn.RemoteAddr())
	conn.Close()
	return true
}

func scanPorts(host string) PortStatus {
	start := time.Now()

	var wg sync.WaitGroup

	var ports []PortInfo
	ports = append(ports, CriticalPorts...)
	ports = append(ports, CommonPorts...)
	ports = append(ports, OptionalPorts...)

	for _, port := range ports {
		wg.Add(1)
		go checkPort(host, port.Port, port.Protocol, &wg)
	}
	wg.Wait()
	duration := time.Since(start)
	fmt.Printf("Port scan completed in %v\n", duration)

	return PortStatus{}
}
