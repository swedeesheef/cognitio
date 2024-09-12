package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

// Result structure to hold IP and response/output
type Result struct {
	IP     net.IP
	Output string
	Error  error
}

func main() {
	// Check if we have the necessary permissions (root on Unix, admin on Windows)
	checkPermissions()

	fmt.Println("Starting ARP scan...")

	// Determine the OS and run the appropriate ARP scan function
	switch runtime.GOOS {
	case "windows":
		runWindowsARPScan()
	case "linux", "darwin":
		runUnixARPScan()
	default:
		log.Fatalf("Unsupported OS: %s", runtime.GOOS)
	}
}

// checkPermissions ensures the program is run with elevated privileges (root on Unix, admin on Windows)
func checkPermissions() {
	switch runtime.GOOS {
	case "linux", "darwin":
		// Check for root privileges on Linux/macOS
		if os.Geteuid() != 0 {
			log.Fatalf("This program requires root privileges. Please run with sudo.")
		}
	case "windows":
		// On Windows, we attempt to check for administrator privileges
		if !isWindowsAdmin() {
			log.Fatalf("This program requires Administrator privileges. Please run as Administrator.")
		}
	}
}

// isWindowsAdmin checks if the current user has Administrator privileges on Windows
func isWindowsAdmin() bool {
	// Try to open the C:\\Windows directory with write access to check for admin rights
	_, err := os.OpenFile("C:\\Windows\\system32\\config", os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	return true
}

// runUnixARPScan performs an ARP scan on Unix-like systems (Linux/macOS)
func runUnixARPScan() {
	// Get local network details (interface, IP, and subnet mask)
	iface, network := getLocalNetwork()

	// Exclude network and broadcast addresses
	broadcast := getBroadcastAddress(network)

	// WaitGroup to ensure all goroutines complete
	var wg sync.WaitGroup

	// Create a channel to collect the results
	results := make(chan Result, 256)

	// Iterate over each IP address in the subnet and send ARP requests concurrently
	for ip := network.IP.Mask(network.Mask); network.Contains(ip); incIP(ip) {
		// Skip if it's the loopback, network address, or broadcast address
		if isLoopback(ip) || ip.Equal(network.IP) || ip.Equal(broadcast) {
			continue
		}

		// Make a copy of the IP address for each Goroutine
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)

		// Increment the WaitGroup counter
		wg.Add(1)

		// Launch a goroutine to handle the ARP request for this IP address
		go func(ip net.IP) {
			defer wg.Done() // Decrement the WaitGroup counter when done

			// Send an ARP request using the arping command
			cmd := exec.Command("arping", "-c", "1", "-I", iface.Name, ip.String())
			output, err := cmd.CombinedOutput()

			// Send the result back through the channel
			results <- Result{IP: ip, Output: string(output), Error: err}
		}(ipCopy) // Pass the copied IP address to the Goroutine
	}

	// Close the results channel once all Goroutines have finished
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and display results, only if there's a valid response
	for res := range results {
		// Only print valid responses
		if res.Error == nil && len(res.Output) > 0 {
			fmt.Printf("ARP Request: Who has %s?\n", res.IP)
			fmt.Println(res.Output)
		}
	}
}

// runWindowsARPScan performs an ARP scan on Windows using native tools
func runWindowsARPScan() {
	// Get local network details (interface, IP, and subnet mask)
	_, network := getLocalNetwork()

	// Exclude network and broadcast addresses
	broadcast := getBroadcastAddress(network)

	// WaitGroup to ensure all goroutines complete
	var wg sync.WaitGroup

	// Create a channel to collect the results
	results := make(chan Result, 256)

	// Iterate over each IP address in the subnet and send ARP requests concurrently
	for ip := network.IP.Mask(network.Mask); network.Contains(ip); incIP(ip) {
		// Skip if it's the loopback, network address, or broadcast address
		if isLoopback(ip) || ip.Equal(network.IP) || ip.Equal(broadcast) {
			continue
		}

		// Make a copy of the IP address for each Goroutine
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)

		// Increment the WaitGroup counter
		wg.Add(1)

		// Launch a goroutine to handle the ARP request for this IP address
		go func(ip net.IP) {
			defer wg.Done() // Decrement the WaitGroup counter when done

			// Use nping from Nmap to send ARP requests
			cmd := exec.Command("nping", "--arp", "--arp-type", "request", "--dest-ip", ip.String())
			output, err := cmd.CombinedOutput()

			// Send the result back through the channel
			results <- Result{IP: ip, Output: string(output), Error: err}
		}(ipCopy) // Pass the copied IP address to the Goroutine
	}

	// Close the results channel once all Goroutines have finished
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and display results, only if there's a valid response
	for res := range results {
		// Only print valid responses
		if res.Error == nil && len(res.Output) > 0 {
			fmt.Printf("ARP Request: Who has %s?\n", res.IP)
			fmt.Println(res.Output)
		}
	}
}

// getLocalNetwork retrieves the IP address and subnet mask of the first network interface it finds
func getLocalNetwork() (*net.Interface, *net.IPNet) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Error retrieving interfaces: %v", err)
	}

	// Find the first active interface with an IPv4 address
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && !isLoopback(ipNet.IP) {
				return &iface, ipNet
			}
		}
	}

	log.Fatalf("No active network interface found")
	return nil, nil
}

// getBroadcastAddress calculates the broadcast address for a given network
func getBroadcastAddress(network *net.IPNet) net.IP {
	// Only proceed if we are dealing with an IPv4 address
	ipv4 := network.IP.To4()
	if ipv4 == nil {
		log.Fatalf("Not an IPv4 address")
	}

	// Calculate the broadcast address for the given IPv4 network
	broadcast := make(net.IP, len(ipv4))
	copy(broadcast, ipv4)
	for i := range broadcast {
		broadcast[i] |= ^network.Mask[i]
	}
	return broadcast
}

// isLoopback checks if an IP address is in the loopback range (127.0.0.0/8)
func isLoopback(ip net.IP) bool {
	return ip.IsLoopback() || ip.To4()[0] == 127
}

// incIP increments an IP address by one
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

