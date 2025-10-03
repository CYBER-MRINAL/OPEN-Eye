// Author = CYBER-MRINAL
// Website = https://cyber-mrinal.github.io/omswastra

package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ScanType defines type of scan
type ScanType string

const (
	TCPConnect ScanType = "tcp"
	TCPSYN     ScanType = "syn"
	UDPScan    ScanType = "udp"
)

// ScanResult holds individual port info
type ScanResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// Global flags
var (
	target      string
	portList    string
	scanType    string
	timeout     int
	concurrency int
	jsonOutput  bool
	csvOutput   string
	verbose     bool
	retries     int
	helpFlag    bool
)

func init() {
	flag.StringVar(&target, "host", "", "Target host or IP (required)")
	flag.StringVar(&portList, "p", "1-1024", "Port range (e.g., 22,80,443 or 1-1024)")
	flag.StringVar(&scanType, "s", "tcp", "Scan type: tcp (connect), syn (requires root), udp (basic)")
	flag.IntVar(&timeout, "timeout", 2, "Timeout per port in seconds")
	flag.IntVar(&concurrency, "T", 200, "Number of concurrent workers")
	flag.BoolVar(&jsonOutput, "json", false, "Output results as JSON (prints to stdout)")
	flag.StringVar(&csvOutput, "csv", "", "Write CSV output to file path (optional)")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.IntVar(&retries, "retries", 1, "Number of retries per port on failure")
	flag.BoolVar(&helpFlag, "h", false, "Show help")
	flag.Parse()

	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: -host is required. Example: openeye -host example.com -p 1-1000 -T 200 -timeout 2")
		flag.Usage()
		os.Exit(1)
	}
}

// parsePorts parses port ranges and comma-separated lists and returns a sorted unique slice
func parsePorts(ports string) []int {
	set := make(map[int]struct{})
	parts := strings.Split(ports, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			r := strings.SplitN(p, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(r[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(r[1]))
			if err1 != nil || err2 != nil || start < 1 || end < 1 || start > 65535 || end > 65535 || start > end {
				continue
			}
			for i := start; i <= end; i++ {
				set[i] = struct{}{}
			}
		} else {
			val, err := strconv.Atoi(p)
			if err != nil || val < 1 || val > 65535 {
				continue
			}
			set[val] = struct{}{}
		}
	}
	var result []int
	for k := range set {
		result = append(result, k)
	}
	sort.Ints(result)
	return result
}

// lightweight host check: resolves DNS and tries a few common TCP ports to verify reachability
func pingHost(ctx context.Context, host string, timeoutSec int) bool {
	// try DNS resolve first
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		if verbose {
			fmt.Fprintf(os.Stderr, "[!] DNS lookup failed for %s: %v\n", host, err)
		}
		return false
	}

	common := []int{80, 443, 22}
	c := make(chan bool, len(common))
	for _, p := range common {
		go func(port int) {
			d := time.Duration(timeoutSec) * time.Second
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), d)
			if err != nil {
				c <- false
				return
			}
			conn.Close()
			c <- true
		}(p)
	}
	// if any succeed, host is up
	for i := 0; i < len(common); i++ {
		if <-c {
			return true
		}
	}
	return false
}

// bannerProbe sends small protocol probes for common services to elicit banners
func bannerProbe(conn net.Conn, port int) string {
	// choose a probe based on port
	probe := ""
	switch port {
	case 80, 8080, 8000, 8888:
		probe = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
	case 443:
		// can't probe TLS without TLS handshake. skip for now.
		probe = ""
	case 21:
		// FTP will normally send banner on connect
		probe = ""
	case 25:
		probe = "HELO example.com\r\n"
	case 110:
		probe = "\r\n"
	case 143:
		probe = "\r\n"
	default:
		probe = "\r\n"
	}

	if probe != "" {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte(probe))
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(conn)
	var out []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		out = append(out, strings.TrimSpace(line))
		if len(out) >= 8 { // limit number of lines
			break
		}
	}
	return strings.Join(out, " ")
}

// serviceFromPort maps common port -> service name
func serviceFromPort(port int) string {
	services := map[int]string{
		20:   "FTP-data",
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		67:   "DHCP",
		68:   "DHCP",
		80:   "HTTP",
		110:  "POP3",
		111:  "rpcbind",
		123:  "NTP",
		143:  "IMAP",
		161:  "SNMP",
		389:  "LDAP",
		443:  "HTTPS",
		3306: "MySQL",
		3389: "RDP",
		5900: "VNC",
		6379: "Redis",
		8000: "HTTP-alt",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return ""
}

// detect service heuristically from banner
func detectServiceFromBanner(banner string, fallbackPort int) string {
	b := strings.ToLower(banner)
	if strings.Contains(b, "ssh") {
		return "SSH"
	}
	if strings.Contains(b, "http") || strings.Contains(b, "html") || strings.Contains(b, "server:") {
		return "HTTP"
	}
	if strings.Contains(b, "smtp") || strings.Contains(b, "mail") {
		return "SMTP"
	}
	if strings.Contains(b, "mysql") {
		return "MySQL"
	}
	if s := serviceFromPort(fallbackPort); s != "" {
		return s
	}
	return ""
}

// tcpConnectScan with retries and banner grabbing
func tcpConnectScan(ctx context.Context, host string, port int, timeoutSec int, retries int) ScanResult {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	res := ScanResult{Port: port, Protocol: "tcp"}
	d := time.Duration(timeoutSec) * time.Second
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		conn, err := net.DialTimeout("tcp", address, d)
		if err != nil {
			lastErr = err
			// small backoff before retry
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
			continue
		}
		defer conn.Close()
		res.State = "open"
		// try to grab banner
		banner := bannerProbe(conn, port)
		banner = strings.TrimSpace(banner)
		if len(banner) > 200 {
			banner = banner[:200]
		}
		res.Banner = banner
		// service detection
		if svc := detectServiceFromBanner(banner, port); svc != "" {
			res.Service = svc
		} else {
			res.Service = serviceFromPort(port)
		}
		return res
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[debug] port %d closed or filtered: %v\n", port, lastErr)
	}
	res.State = "closed"
	return res
}

// udpScan (basic): sends an empty packet to see if something responds. Not reliable.
func udpScan(ctx context.Context, host string, port int, timeoutSec int) ScanResult {
	res := ScanResult{Port: port, Protocol: "udp"}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), time.Duration(timeoutSec)*time.Second)
	if err != nil {
		res.State = "closed"
		return res
	}
	defer conn.Close()
	// write a minimal payload
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, _ = conn.Write([]byte("\n"))
	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	n, _ := conn.Read(buf)
	if n > 0 {
		res.State = "open"
		res.Banner = strings.TrimSpace(string(buf[:n]))
		res.Service = serviceFromPort(port)
		return res
	}
	res.State = "open|filtered"
	return res
}

// printTable prints results in a neat ASCII table
func printTable(results []ScanResult) {
	fmt.Println("+------+---------+-----------+----------------------+--------------------------+")
	fmt.Println("| Port | Protocol| State     | Service              | Banner                   |")
	fmt.Println("+------+---------+-----------+----------------------+--------------------------+")
	for _, r := range results {
		banner := r.Banner
		if len(banner) > 24 {
			banner = banner[:21] + "..."
		}
		service := r.Service
		if service == "" {
			service = "-"
		}
		fmt.Printf("| %-4d | %-7s | %-9s | %-20s | %-24s |\n", r.Port, r.Protocol, r.State, service, banner)
	}
	fmt.Println("+------+---------+-----------+----------------------+--------------------------+")
}

func writeCSV(path string, results []ScanResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"port", "protocol", "state", "service", "banner"})
	for _, r := range results {
		_ = w.Write([]string{strconv.Itoa(r.Port), r.Protocol, r.State, r.Service, r.Banner})
	}
	return nil
}

func main() {
	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	// handle Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\n[!] Received interrupt, shutting down gracefully...")
		cancel()
	}()

	// SYN scan warning
	if ScanType(scanType) == TCPSYN {
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "Error: -s syn requires root privileges and raw socket/pcap support. Not implemented here.")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "Note: SYN scan mode requested. This program currently does not implement raw SYN scanning. It will fallback to TCP connect.")
	}

	fmt.Printf("[*] OPEN-Eye Scanner on %s\n", target)
	if !pingHost(ctx, target, timeout) {
		fmt.Printf("[!] Host %s appears offline or not responding to common TCP ports. Proceeding anyway...\n", target)
	}

	ports := parsePorts(portList)
	if len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "No valid ports to scan after parsing.")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	resultsCh := make(chan ScanResult, len(ports))
	sem := make(chan struct{}, concurrency)

	fmt.Printf("[*] Running %s scan on %s with %d workers, timeout=%ds, retries=%d\n", scanType, target, concurrency, timeout, retries)

	for _, port := range ports {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			var res ScanResult
			switch ScanType(scanType) {
			case TCPConnect:
				res = tcpConnectScan(ctx, target, p, timeout, retries)
			case UDPScan:
				res = udpScan(ctx, target, p, timeout)
			case TCPSYN:
				// fallback behavior: use connect scan if raw SYN isn't available
				res = tcpConnectScan(ctx, target, p, timeout, retries)
			default:
				res = tcpConnectScan(ctx, target, p, timeout, retries)
			}
			resultsCh <- res
		}(port)
	}

	wg.Wait()
	close(resultsCh)

	var final []ScanResult
	for r := range resultsCh {
		if r.State == "open" || strings.Contains(r.State, "open") {
			final = append(final, r)
		}
	}

	sort.Slice(final, func(i, j int) bool { return final[i].Port < final[j].Port })

	if jsonOutput {
		data, _ := json.MarshalIndent(final, "", "  ")
		fmt.Println(string(data))
	} else {
		printTable(final)
		if csvOutput != "" {
			if err := writeCSV(csvOutput, final); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write CSV: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Wrote CSV to %s\n", csvOutput)
			}
		}
		// reverse DNS and OS guess
		if len(final) > 0 {
			if names, err := net.LookupAddr(target); err == nil && len(names) > 0 {
				fmt.Printf("[*] Reverse DNS: %s\n", names[0])
			}
			fmt.Printf("[*] OS Detection Guess: %s\n", detectOS(final))
		}
		fmt.Printf("[*] Scan complete in %s\n", time.Since(start))
	}
}

// OS detection based on open ports
func detectOS(openPorts []ScanResult) string {
	var ports []int
	for _, r := range openPorts {
		if r.State == "open" {
			ports = append(ports, r.Port)
		}
	}
	if contains(ports, 135) || contains(ports, 445) {
		return "Windows"
	} else if contains(ports, 22) || contains(ports, 80) || contains(ports, 443) {
		return "Linux/Unix"
	}
	return "Unknown"
}

// Helper
func contains(slice []int, item int) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

