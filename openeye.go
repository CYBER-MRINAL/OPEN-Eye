// Author = CYBER-MRINAL (improved by assistant)
// Website = https://cyber-mrinal.github.io/omswastra
// Improved: colorful, progress, better banner grabbing, SNI-aware TLS, HTTP Host header, reverse DNS,
// token-bucket rate limiting, more accurate heuristics, JSON/CSV output, and safer concurrency controls.

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// max64 returns the larger of two int64 numbers
func max64(a, b int64) int64 {
    if a > b {
        return a
    }
    return b
}

// ANSI color helpers (no external deps)
const (
	clrReset  = "\x1b[0m"
	clrRed    = "\x1b[31m"
	clrGreen  = "\x1b[32m"
	clrYellow = "\x1b[33m"
	clrBlue   = "\x1b[34m"
	clrMag    = "\x1b[35m"
	clrCyan   = "\x1b[36m"
	clrGray   = "\x1b[90m"
)

type ScanType string

const (
	TCPConnect ScanType = "tcp"
	UDPScan    ScanType = "udp"
)

// Result model
type ScanResult struct {
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Protocol string  `json:"protocol"`
	State    string  `json:"state"`
	Service  string  `json:"service,omitempty"`
	Banner   string  `json:"banner,omitempty"`
	Extra    string  `json:"extra,omitempty"`
	RTT      float64 `json:"rtt_ms,omitempty"`
	Attempt  int     `json:"attempt,omitempty"`
	ScanTime string  `json:"scan_time,omitempty"`
}

type ScanReport struct {
	TargetInput string       `json:"target_input"`
	Targets     []string     `json:"targets"`
	Type        string       `json:"type"`
	ScanTime    string       `json:"scan_time"`
	Duration    string       `json:"duration"`
	Results     []ScanResult `json:"results"`
}

// CLI flags
var (
	hostFlag      string
	hostsFile     string
	portListFlag  string
	scanTypeFlag  string
	timeoutSec    int
	concurrency   int
	jsonOutput    bool
	csvOutput     string
	verbose       bool
	retries       int
	helpFlag      bool
	ratePerSecond int
	showAll       bool
	onlyTop       bool
)

func init() {
	flag.StringVar(&hostFlag, "host", "", "Target host or IP (single). Mutually exclusive with -hosts")
	flag.StringVar(&hostsFile, "hosts", "", "Path to file with hosts (one per line) or CIDR (e.g., 10.0.0.0/24)")
	flag.StringVar(&portListFlag, "p", "1-1024", "Port list (e.g., 22,80,443 or 1-1024)")
	flag.StringVar(&scanTypeFlag, "s", "tcp", "Scan type: tcp (connect). udp is basic and unreliable.")
	flag.IntVar(&timeoutSec, "timeout", 2, "Timeout per port in seconds")
	flag.IntVar(&concurrency, "T", 200, "Number of concurrent workers")
	flag.IntVar(&ratePerSecond, "rps", 0, "Rate limit connections per second (0 = unlimited)")
	flag.BoolVar(&jsonOutput, "json", false, "Output full results as JSON")
	flag.StringVar(&csvOutput, "csv", "", "Write CSV output to file path")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.IntVar(&retries, "retries", 2, "Number of retries per port on failure (with backoff)")
	flag.BoolVar(&helpFlag, "h", false, "Show help")
	flag.BoolVar(&showAll, "all", false, "Show all ports in final output (not only open)")
	flag.BoolVar(&onlyTop, "top", false, "Only scan top common ports (fast)")
}

// common top ports
var topPorts = []int{80, 443, 22, 21, 23, 25, 53, 3389, 3306, 5900, 8080, 8443, 139, 445, 111}

func main() {
	flag.Parse()
	if helpFlag {
		flag.Usage()
		return
	}
	if hostFlag == "" && hostsFile == "" {
		fmt.Fprintln(os.Stderr, "Error: either -host or -hosts is required")
		flag.Usage()
		os.Exit(1)
	}

	targets := expandTargets(hostFlag, hostsFile)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "No targets to scan after parsing.")
		os.Exit(1)
	}

	var ports []int
	if onlyTop {
		ports = topPorts
	} else {
		ports = parsePorts(portListFlag)
	}
	if len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "No valid ports to scan after parsing -p.")
		os.Exit(1)
	}
	ordered := prioritizePorts(ports, topPorts)

	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	// handle Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\n[!] Received interrupt, shutting down...")
		cancel()
	}()

	// rate limiter token-bucket
	var rateCh <-chan time.Time
	if ratePerSecond > 0 {
		interval := time.Second / time.Duration(max(1, ratePerSecond))
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateCh = ticker.C
	}

	results := runScan(ctx, targets, ordered, ScanType(scanTypeFlag), timeoutSec, concurrency, retries, rateCh)

	duration := time.Since(start)
	report := ScanReport{
		TargetInput: fmt.Sprintf("host=%s hostsfile=%s", hostFlag, hostsFile),
		Targets:     targets,
		Type:        string(TCPConnect),
		ScanTime:    start.Format(time.RFC3339),
		Duration:    duration.String(),
		Results:     results,
	}

	// Output
	if jsonOutput {
		out, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(out))
	} else {
		printPretty(report, showAll)
		if csvOutput != "" {
			if err := writeCSV(csvOutput, report.Results); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write CSV: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Wrote CSV to %s\n", csvOutput)
			}
		}
	}
}

// Helpers
func max(a, b int) int { if a>b { return a }; return b }

func expandTargets(single, hostsFile string) []string {
	set := make(map[string]struct{})
	if single != "" {
		single = strings.TrimSpace(single)
		set[single] = struct{}{}
	}
	if hostsFile != "" {
		f, err := os.Open(hostsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open hosts file: %v\n", err)
			return keys(set)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") { continue }
			if strings.Contains(line, "/") {
				ips := cidrToIPs(line)
				for _, ip := range ips { set[ip] = struct{}{} }
			} else { set[line] = struct{}{} }
		}
	}
	return keys(set)
}

func keys(m map[string]struct{}) []string {
	var out []string
	for k := range m { out = append(out, k) }
	sort.Strings(out)
	return out
}

func cidrToIPs(cidr string) []string {
	var ips []string
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil { return ips }
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 { return ips[1:len(ips)-1] }
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip)-1; j>=0; j-- {
		ip[j]++
		if ip[j] > 0 { break }
	}
}

func parsePorts(ports string) []int {
	set := make(map[int]struct{})
	parts := strings.Split(ports, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p=="" { continue }
		if strings.Contains(p, "-") {
			r := strings.SplitN(p, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(r[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(r[1]))
			if err1!=nil || err2!=nil || start<1 || end<1 || start>65535 || end>65535 || start> end { continue }
			for i:=start; i<= end; i++ { set[i] = struct{}{} }
		} else {
			val, err := strconv.Atoi(p)
			if err!=nil || val<1 || val>65535 { continue }
			set[val] = struct{}{}
		}
	}
	var result []int
	for k := range set { result = append(result, k) }
	sort.Ints(result)
	return result
}

func prioritizePorts(all []int, priority []int) []int {
	prioritySet := make(map[int]int)
	for i,p := range priority { prioritySet[p] = i }
	sort.Slice(all, func(i,j int) bool {
		pi, iok := prioritySet[all[i]]
		pj, jok := prioritySet[all[j]]
		if iok && !jok { return true }
		if !iok && jok { return false }
		if iok && jok { return pi < pj }
		return all[i] < all[j]
	})
	return all
}

// runScan orchestrates scanning and progress
func runScan(ctx context.Context, targets []string, ports []int, sType ScanType, timeoutSec, workers, retries int, rateCh <-chan time.Time) []ScanResult {
	var resultsMu sync.Mutex
	var results []ScanResult

	totalTasks := int64(len(targets) * len(ports))
	var doneTasks int64

	tasks := make(chan struct{ host string; port int }, workers*10)
	var wg sync.WaitGroup

	// before launching progress goroutine
	start := time.Now()

	// progress goroutine
	ctxProgress, cancelProgress := context.WithCancel(context.Background())
	go func() {
	    spinner := []string{"|","/","-","\\"}
	    si := 0
	    for {
	        select {
	        case <-ctxProgress.Done():
	            return
	        default:
	            d := atomic.LoadInt64(&doneTasks)
				pct := float64(d) / float64(max64(1, int64(totalTasks))) * 100.0
	            elapsed := humanDuration(time.Since(start))
	            fmt.Fprintf(os.Stderr, "%s[%s] %d/%d (%.1f%%) %sElapsed:%s %s\r",
	                clrCyan, spinner[si%len(spinner)], d, totalTasks, pct,
	                clrReset, elapsed, clrReset)
	            si++
	            time.Sleep(250 * time.Millisecond)
	        }
	    }
	}()
	
	// worker pool
	for i:=0; i< workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for t := range tasks {
				if ctx.Err() != nil { return }
				if rateCh != nil {
					select { case <-rateCh: case <-ctx.Done(): return }
				}
				start := time.Now()
				res := scanPortWithRetries(ctx, t.host, t.port, sType, timeoutSec, retries)
				res.RTT = float64(time.Since(start).Milliseconds())
				resultsMu.Lock()
				results = append(results, res)
				resultsMu.Unlock()
				atomic.AddInt64(&doneTasks, 1)
				if verbose {
					fmt.Fprintf(os.Stderr, "%s[w%d]%s %s:%d %s (%s)\n", clrGray, id, clrReset, t.host, t.port, res.State, res.Service)
				}
			}
		}(i)
	}

	// enqueue
	enqueue:
	for _, h := range targets {
		for _, p := range ports {
			select { case <- ctx.Done(): break enqueue; default: }
			tasks <- struct{ host string; port int }{ host: h, port: p }
		}
	}
	close(tasks)
	wg.Wait()
	cancelProgress()

	// filter and sort
	var filtered []ScanResult
	for _, r := range results {
		if r.State == "open" || strings.Contains(r.State, "open") || showAll {
			filtered = append(filtered, r)
		}
	}
	sort.Slice(filtered, func(i,j int) bool {
		if filtered[i].Host == filtered[j].Host { return filtered[i].Port < filtered[j].Port }
		return filtered[i].Host < filtered[j].Host
	})
	return filtered
}

func scanPortWithRetries(ctx context.Context, host string, port int, sType ScanType, timeoutSec int, retries int) ScanResult {
	var last ScanResult
	for attempt:=0; attempt<= retries; attempt++ {
		start := time.Now()
		res := scanPort(ctx, host, port, sType, timeoutSec)
		res.Attempt = attempt+1
		res.RTT = float64(time.Since(start).Milliseconds())
		res.ScanTime = time.Now().Format(time.RFC3339)
		last = res
		if res.State == "open" || res.State == "closed" { return res }
		// backoff
		backoff := time.Duration(150*(attempt+1)) * time.Millisecond
		select { case <- time.After(backoff): case <- ctx.Done(): return res }
	}
	return last
}

func dialWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.Dial(network, address)
}

func scanPort(ctx context.Context, host string, port int, sType ScanType, timeoutSec int) ScanResult {
	res := ScanResult{ Host: host, Port: port, Protocol: "tcp", State: "closed" }
	address := net.JoinHostPort(host, strconv.Itoa(port))
	timeout := time.Duration(timeoutSec) * time.Second

	conn, err := dialWithTimeout("tcp", address, timeout)
	if err != nil {
		if isTimeoutErr(err) { res.State = "filtered" } else { res.State = "closed" }
		return res
	}
	defer conn.Close()
	res.State = "open"
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// TLS-aware probes for common TLS ports
	if port==443 || port==8443 || port==9443 {
		if tr := probeTLS(host, port, timeout); tr != nil {
			res.Banner = tr.Banner
			res.Extra = tr.Extra
			res.Service = tr.Service
			return res
		}
	}

	// HTTP-like
	if looksLikeHTTP(port) {
		if hr := httpHeadProbe(host, port, timeout); hr != nil {
			res.Banner = hr.Banner
			res.Extra = hr.Extra
			res.Service = hr.Service
			return res
		}
	}

	// port-specific minimal probes
	if port == 22 {
		b := readBanner(conn)
		res.Banner = b
		res.Service = fingerprintService(b, port)
		return res
	}

	// generic banner
	b := genericBannerProbe(conn)
	res.Banner = b
	if svc := fingerprintService(b, port); svc != "" { res.Service = svc } else { res.Service = wellKnownService(port) }

	// try reverse DNS for extra info (best-effort)
	if names, err := net.LookupAddr(host); err==nil && len(names)>0 {
		res.Extra = strings.TrimSpace(names[0])
	}
	return res
}

func isTimeoutErr(err error) bool {
	if err==nil { return false }
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "timeout") || strings.Contains(s, "i/o timeout") || strings.Contains(s, "refused")
}

func readBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil { return "" }
	return strings.TrimSpace(string(buf[:n]))
}

func genericBannerProbe(conn net.Conn) string {
	conn.SetWriteDeadline(time.Now().Add(800 * time.Millisecond))
	_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	r := bufio.NewReader(conn)
	var lines []string
	for i:=0; i<16; i++ {
		line, err := r.ReadString('\n')
		if err!=nil { break }
		line = strings.TrimSpace(line)
		if line!="" { lines = append(lines, line) }
	}
	if len(lines)==0 {
		// fallback read raw bytes
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n>0 { return strings.TrimSpace(string(buf[:n])) }
	}
	return strings.Join(lines, " ")
}

type probeResult struct{ Banner, Extra, Service string }

func probeTLS(host string, port int, timeout time.Duration) *probeResult {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: host}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err!=nil { return nil }
	defer conn.Close()
	state := conn.ConnectionState()
	peerCert := ""
	if len(state.PeerCertificates)>0 {
		c := state.PeerCertificates[0]
		peerCert = fmt.Sprintf("CN=%s, Issuer=%s", c.Subject.CommonName, c.Issuer.CommonName)
	}
	// try HTTP over TLS if possible
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	banner := strings.TrimSpace(string(buf[:n]))
	return &probeResult{ Banner: banner, Extra: peerCert, Service: "HTTPS" }
}

func httpHeadProbe(host string, port int, timeout time.Duration) *probeResult {
	scheme := "http"
	if port==443 || port==8443 { scheme = "https" }
	u := url.URL{ Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: "/" }
	client := http.Client{ Timeout: timeout }
	// try HEAD with Host header
	req, _ := http.NewRequest("HEAD", u.String(), nil)
	req.Header.Set("User-Agent", "OPEN-Eye2/1.0")
	req.Host = host
	resp, err := client.Do(req)
	if err!=nil {
		// fallback GET
		resp2, err2 := client.Get(u.String())
		if err2!=nil { return nil }
		defer resp2.Body.Close()
		title := extractHTMLTitle(resp2.Body)
		server := resp2.Header.Get("Server")
		banner := fmt.Sprintf("Server: %s", server)
		return &probeResult{ Banner: banner, Extra: title, Service: "HTTP" }
	}
	defer resp.Body.Close()
	title := extractHTMLTitle(resp.Body)
	server := resp.Header.Get("Server")
	banner := fmt.Sprintf("Server: %s", server)
	return &probeResult{ Banner: banner, Extra: title, Service: "HTTP" }
}

func extractHTMLTitle(r io.Reader) string {
	b := make([]byte, 8192)
	n, _ := r.Read(b)
	s := string(b[:n])
	l := strings.ToLower(s)
	start := strings.Index(l, "<title>")
	end := strings.Index(l, "</title>")
	if start>=0 && end>start {
		title := s[start+7:end]
		title = strings.TrimSpace(html.EscapeString(title))
		return title
	}
	return ""
}

func looksLikeHTTP(port int) bool {
	httpPorts := map[int]struct{}{80:{},8080:{},8000:{},8888:{},8081:{},3000:{},5000:{}}
	_, ok := httpPorts[port]
	return ok || port==443 || port==8443
}

func fingerprintService(banner string, port int) string {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "ssh-"): return "SSH"
	case strings.Contains(b, "smtp") || strings.Contains(b, "ehlo"): return "SMTP"
	case strings.Contains(b, "mysql") || strings.Contains(b, "mysql") : return "MySQL"
	case strings.Contains(b, "ftp") || strings.Contains(b, "ftpd"): return "FTP"
	case strings.Contains(b, "redis") : return "Redis"
	case strings.Contains(b, "vnc") : return "VNC"
	case strings.Contains(b, "http") || strings.Contains(b, "server:"): return "HTTP"
	}
	return wellKnownService(port)
}

func wellKnownService(port int) string {
	services := map[int]string{20:"FTP-data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",67:"DHCP",68:"DHCP",80:"HTTP",110:"POP3",111:"rpcbind",123:"NTP",143:"IMAP",161:"SNMP",389:"LDAP",443:"HTTPS",3306:"MySQL",3389:"RDP",5900:"VNC",6379:"Redis",8000:"HTTP-alt"}
	if s, ok := services[port]; ok { return s }
	return ""
}

// pretty table with colors
func printPretty(r ScanReport, showAll bool) {
	fmt.Printf("%s[*]%s OPEN-Eye Scanner - targets: %d, results: %d, duration: %s\n", clrMag, clrReset, len(r.Targets), len(r.Results), r.Duration)
	if len(r.Results)==0 { fmt.Println("No ports matched criteria."); return }

	// header
	fmt.Printf("%s+------------------------------+------+------+--------------+--------------------------------+%s\n", clrCyan, clrReset)
	fmt.Printf("%s| %-28s | %-4s | %-4s | %-11s | %-28s |%s\n", clrCyan, "Host", "Port", "Proto", "Service", "Extra", clrReset)
	fmt.Printf("%s+------------------------------+------+------+--------------+--------------------------------+%s\n", clrCyan, clrReset)
	for _, rr := range r.Results {
		stateClr := clrGreen
		if strings.Contains(strings.ToLower(rr.State), "filtered") { stateClr = clrYellow }
		if strings.Contains(strings.ToLower(rr.State), "closed") { stateClr = clrRed }
		extra := rr.Extra
		if len(extra) > 28 { extra = extra[:25] + "..." }
		svc := rr.Service
		if svc == "" { svc = "-" }
		fmt.Printf("| %-28s | %4d | %4s | %-11s | %-28s |\n", rr.Host, rr.Port, stateClr+rr.Protocol+clrReset, svc, extra)
	}
	fmt.Printf("%s+------------------------------+------+------+--------------+--------------------------------+%s\n", clrCyan, clrReset)
}

func writeCSV(path string, results []ScanResult) error {
	f, err := os.Create(path)
	if err!=nil { return err }
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"host","port","protocol","state","service","banner","extra","rtt_ms","attempt","scan_time"})
	for _, r := range results {
		_ = w.Write([]string{ r.Host, strconv.Itoa(r.Port), r.Protocol, r.State, r.Service, r.Banner, r.Extra, fmt.Sprintf("%.2f", r.RTT), strconv.Itoa(r.Attempt), r.ScanTime })
	}
	return nil
}

func humanDuration(d time.Duration) string {
	if d < time.Second { return d.String() }
	secs := int64(d.Seconds())
	h := secs/3600; m := (secs%3600)/60; s := secs%60
	if h>0 { return fmt.Sprintf("%dh%dm%ds", h,m,s) }
	if m>0 { return fmt.Sprintf("%dm%ds", m,s) }
	return fmt.Sprintf("%ds", s)
}

