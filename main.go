package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	timeout    = 8 * time.Second
	userAgent  = "Mozilla/5.0 (compatible; PathBruter/1.0)"
	concurrent = 100
)

var (
	okCodes        = map[int]bool{200: true, 201: true, 202: true, 204: true}
	protectedCodes = map[int]bool{401: true, 403: true}
	redirectCodes  = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}
)

type Result struct {
	URL      string
	Status   int
	Length   int
	Location string
	WAF      string
	Label    string
}

var wafSignatures = map[string]string{
	"cloudflare":   "Cloudflare",
	"sucuri":       "Sucuri",
	"incapsula":    "Imperva Incapsula",
	"imperva":      "Imperva",
	"akamai":       "Akamai",
	"aws":          "AWS WAF",
	"barracuda":    "Barracuda",
	"f5":           "F5 BIG-IP",
	"fortiweb":     "FortiWeb",
	"mod_security": "ModSecurity",
	"wordfence":    "Wordfence",
}

func loadPaths(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "://") {
			parts := strings.SplitN(line, "://", 2)
			if len(parts) == 2 {
				path := parts[1]
				if idx := strings.Index(path, "/"); idx >= 0 {
					line = path[idx:]
				} else {
					continue
				}
			}
		}
		line = strings.TrimRight(line, "/")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			line = "/" + line
		}
		seen[line] = true
	}

	var paths []string
	for p := range seen {
		paths = append(paths, p)
	}
	return paths, nil
}

func detectWAF(resp *http.Response, body string) string {
	var sb strings.Builder
	for k, v := range resp.Header {
		sb.WriteString(k)
		sb.WriteString(":")
		sb.WriteString(strings.Join(v, ","))
		sb.WriteString(" ")
	}
	headerText := strings.ToLower(sb.String())
	bodyText := strings.ToLower(body)

	for sig, name := range wafSignatures {
		if strings.Contains(headerText, sig) || strings.Contains(bodyText, sig) {
			return name
		}
	}
	if resp.Header.Get("CF-Ray") != "" || resp.Header.Get("CF-Cache-Status") != "" {
		return "Cloudflare"
	}
	if resp.Header.Get("X-Sucuri-ID") != "" {
		return "Sucuri"
	}
	if resp.Header.Get("X-Iinfo") != "" || resp.Header.Get("X-CDN") != "" {
		return "Imperva"
	}
	return ""
}

func classify(status int) string {
	if okCodes[status] {
		return "OK"
	}
	if protectedCodes[status] {
		return "PROTECTED"
	}
	if redirectCodes[status] {
		return "REDIRECT"
	}
	return "UNKNOWN"
}

func probe(client *http.Client, base, path string, baselineLen int, baselineStatus int) *Result {
	url := strings.TrimRight(base, "/") + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodyStr := string(body)

	// Soft-404 check
	if baselineStatus > 0 && resp.StatusCode == baselineStatus && len(body) == baselineLen {
		return nil
	}

	label := classify(resp.StatusCode)
	if label == "UNKNOWN" {
		return nil
	}

	return &Result{
		URL:      url,
		Status:   resp.StatusCode,
		Length:   len(body),
		Location: resp.Header.Get("Location"),
		WAF:      detectWAF(resp, bodyStr),
		Label:    label,
	}
}

func getBaseline(client *http.Client, base string) (int, int) {
	url := strings.TrimRight(base, "/") + "/" + uuid.New().String()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return len(body), resp.StatusCode
}

func main() {
	fmt.Println("Path Bruter Tool by K5E-ai")
	fmt.Println("=====================================")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Target: ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	if target == "" {
		fmt.Println("[-] No target provided.")
		os.Exit(1)
	}

	fmt.Print("Wordlist file: ")
	wordlist, _ := reader.ReadString('\n')
	wordlist = strings.TrimSpace(wordlist)
	if wordlist == "" {
		fmt.Println("[-] No wordlist provided.")
		os.Exit(1)
	}

	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		fmt.Printf("[-] File not found: %s\n", wordlist)
		os.Exit(1)
	}

	base := strings.TrimRight(target, "/")
	paths, err := loadPaths(wordlist)
	if err != nil || len(paths) == 0 {
		fmt.Println("[-] No paths loaded from wordlist.")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("[+] Target:   %s\n", base)
	fmt.Printf("[+] Wordlist: %s\n", wordlist)
	fmt.Printf("[+] Paths:    %d\n", len(paths))
	fmt.Println()
	fmt.Println("[*] Testing...")
	fmt.Println()

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    concurrent,
		},
	}

	fmt.Println("[*] Probing baseline (soft-404 detection)...")
	baseLen, baseStatus := getBaseline(client, base)
	if baseStatus > 0 {
		fmt.Printf("[*] Baseline: status=%d length=%d\n", baseStatus, baseLen)
	}
	fmt.Println()

	sem := make(chan struct{}, concurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	var results []Result
	wafsFound := make(map[string]bool)

	for _, p := range paths {
		wg.Add(1)
		sem <- struct{}{}

		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()

			res := probe(client, base, path, baseLen, baseStatus)
			mu.Lock()
			defer mu.Unlock()

			if res == nil {
				fmt.Printf("[no]         %s   [filtered]\n", base+path)
				return
			}

			if res.WAF != "" {
				wafsFound[res.WAF] = true
			}

			switch res.Label {
			case "OK":
				fmt.Printf("[OK]         %s   [%d]\n", res.URL, res.Status)
			case "PROTECTED":
				fmt.Printf("[PROTECTED]  %s   [%d]\n", res.URL, res.Status)
			case "REDIRECT":
				loc := ""
				if res.Location != "" {
					loc = " -> " + res.Location
				}
				fmt.Printf("[REDIRECT]   %s   [%d]%s\n", res.URL, res.Status, loc)
			}
			results = append(results, *res)
		}(p)
	}

	wg.Wait()

	// Save
	out, _ := os.Create("found.txt")
	defer out.Close()
	for _, r := range results {
		fmt.Fprintln(out, r.URL)
	}

	fmt.Println()
	fmt.Println("=====================================")

	if len(wafsFound) > 0 {
		var wafList []string
		for w := range wafsFound {
			wafList = append(wafList, w)
		}
		fmt.Printf("[!] WAF Detected: %s\n", strings.Join(wafList, ", "))
	}

	okCount, protCount, redirCount := 0, 0, 0
	for _, r := range results {
		switch r.Label {
		case "OK":
			okCount++
		case "PROTECTED":
			protCount++
		case "REDIRECT":
			redirCount++
		}
	}

	fmt.Printf("[+] OK:         %d\n", okCount)
	fmt.Printf("[+] Protected:  %d\n", protCount)
	fmt.Printf("[+] Redirects:  %d\n", redirCount)
	fmt.Printf("[+] Total:      %d\n", len(results))
	fmt.Println("[+] Saved to:   found.txt")
}
