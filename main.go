package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/schollz/progressbar/v3"
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

type RGB struct{ R, G, B uint8 }

var gradientStops = []RGB{
	{0xFF, 0x00, 0x7F},
	{0x8B, 0x00, 0xFF},
	{0x00, 0x55, 0xFF},
	{0xFF, 0x00, 0x00},
}

func lerp(a, b uint8, t float64) uint8 {
	return uint8(float64(a) + (float64(b)-float64(a))*t)
}

func gradientColor(t float64) RGB {
	if t <= 0 {
		return gradientStops[0]
	}
	if t >= 1 {
		return gradientStops[len(gradientStops)-1]
	}
	segCount := len(gradientStops) - 1
	seg := t * float64(segCount)
	idx := int(math.Floor(seg))
	if idx >= segCount {
		idx = segCount - 1
	}
	localT := seg - float64(idx)
	return RGB{
		R: lerp(gradientStops[idx].R, gradientStops[idx+1].R, localT),
		G: lerp(gradientStops[idx].G, gradientStops[idx+1].G, localT),
		B: lerp(gradientStops[idx].B, gradientStops[idx+1].B, localT),
	}
}

func printGradientLine(s string) {
	n := len(s)
	if n == 0 {
		fmt.Println()
		return
	}
	var sb strings.Builder
	for i, r := range s {
		c := gradientColor(float64(i) / float64(max(n-1, 1)))
		sb.WriteString(fmt.Sprintf("\x1b[38;2;%d;%d;%dm%c", c.R, c.G, c.B, r))
	}
	sb.WriteString("\x1b[0m")
	fmt.Println(sb.String())
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var (
	cCVE       = color.New(color.FgHiCyan, color.Bold)
	cAuthor    = color.New(color.FgHiYellow)
	cPrompt    = color.New(color.FgHiGreen, color.Bold)
	cInfo      = color.New(color.FgHiBlue)
	cOK        = color.New(color.FgHiGreen, color.Bold)
	cProtected = color.New(color.FgHiYellow, color.Bold)
	cRedirect  = color.New(color.FgHiCyan, color.Bold)
	cFail      = color.New(color.FgHiRed)
	cWAF       = color.New(color.FgHiRed, color.Bold)
	cSummary   = color.New(color.FgHiWhite, color.Bold)
	cBox       = color.New(color.FgHiMagenta, color.Bold)
)

type Result struct {
	URL      string
	Status   int
	Length   int
	Location string
	WAF      string
	Label    string
}

func printBanner() {
	skull := []string{
		`         .-.             .-.         `,
		`        /   \           /   \        `,
		`       |     |         |     |       `,
		`       |  .  |         |  .  |       `,
		`       |     |         |     |       `,
		`        \___/  \_____/  \___/        `,
		`       .'   '.  |___|  .'   '.       `,
		`      /       \/     \/       \      `,
		`     |    .-.   .-.   .-.   .-|      `,
		`     |    | |   | |   | |   | |      `,
		`      \   '-'   '-'   '-'   '-'      `,
		`       '-------------------------    `,
		`        |  . . . . . . . . .  |      `,
		`        |  . . . . . . . . .  |      `,
		`         \___________________/       `,
	}
	for _, line := range skull {
		printGradientLine(line)
	}

	title := `P A T H   B R U T E R`
	printGradientLine(title)
	printGradientLine(strings.Repeat("─", len(title)))
	cCVE.Println("  directory / content discovery")
	cAuthor.Println("  by K52-ai")
	fmt.Println()
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
	sort.Strings(paths)
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

	if baselineStatus > 0 && resp.StatusCode == baselineStatus && baselineLen > 0 {
		diff := len(body) - baselineLen
		if diff < 0 {
			diff = -diff
		}
		if float64(diff)/float64(baselineLen) < 0.05 {
			return nil
		}
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
	lengths := make([]int, 0, 3)
	statuses := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		url := strings.TrimRight(base, "/") + "/" + uuid.New().String()
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		lengths = append(lengths, len(body))
		statuses = append(statuses, resp.StatusCode)
	}
	if len(lengths) == 0 {
		return 0, 0
	}
	sort.Ints(lengths)
	median := lengths[len(lengths)/2]
	counts := make(map[int]int)
	for _, s := range statuses {
		counts[s]++
	}
	bestStatus, bestCount := 0, 0
	for s, c := range counts {
		if c > bestCount {
			bestStatus, bestCount = s, c
		}
	}
	return median, bestStatus
}

func promptString(reader *bufio.Reader, label string) string {
	cBox.Print("  ┌─[ ")
	cPrompt.Print(label)
	cBox.Println(" ]")
	cBox.Print("  └──▶ ")
	s, _ := reader.ReadString('\n')
	return strings.TrimSpace(s)
}

func main() {
	var (
		targetFlag   string
		wordlistFlag string
	)
	flag.StringVar(&targetFlag, "u", "", "target URL")
	flag.StringVar(&wordlistFlag, "w", "", "wordlist file")
	flag.Parse()

	printBanner()
	reader := bufio.NewReader(os.Stdin)

	target := targetFlag
	if target == "" {
		target = promptString(reader, "target")
	}
	if target == "" {
		cFail.Println("  [-] No target provided.")
		os.Exit(1)
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	wordlist := wordlistFlag
	if wordlist == "" {
		wordlist = promptString(reader, "wordlist")
	}
	if wordlist == "" {
		cFail.Println("  [-] No wordlist provided.")
		os.Exit(1)
	}
	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		cFail.Printf("  [-] File not found: %s\n", wordlist)
		os.Exit(1)
	}

	base := strings.TrimRight(target, "/")
	paths, err := loadPaths(wordlist)
	if err != nil || len(paths) == 0 {
		cFail.Println("  [-] No paths loaded from wordlist.")
		os.Exit(1)
	}

	fmt.Println()
	cBox.Println("  ╭──────────────────────────────────────╮")
	cInfo.Printf("  │ target    : %-24s│\n", base)
	cInfo.Printf("  │ wordlist  : %-24s│\n", wordlist)
	cInfo.Printf("  │ paths     : %-24d│\n", len(paths))
	cInfo.Printf("  │ workers   : %-24d│\n", concurrent)
	cBox.Println("  ╰──────────────────────────────────────╯")
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

	cInfo.Println("  [*] probing baseline (soft-404 detection, 3 samples)...")
	baseLen, baseStatus := getBaseline(client, base)
	if baseStatus > 0 {
		cInfo.Printf("  [*] baseline: status=%d length=%d\n", baseStatus, baseLen)
	}
	fmt.Println()

	bar := progressbar.NewOptions(len(paths),
		progressbar.OptionSetDescription("  scanning"),
		progressbar.OptionSetWidth(40),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerHead:    "█",
			SaucerPadding: "░",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	jobs := make(chan string, len(paths))
	resultsCh := make(chan Result, len(paths))
	var wg sync.WaitGroup

	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				if res := probe(client, base, path, baseLen, baseStatus); res != nil {
					resultsCh <- *res
				}
				bar.Add(1)
			}
		}()
	}

	go func() {
		for _, p := range paths {
			jobs <- p
		}
		close(jobs)
		wg.Wait()
		close(resultsCh)
	}()

	var results []Result
	wafsFound := make(map[string]bool)
	for r := range resultsCh {
		if r.WAF != "" {
			wafsFound[r.WAF] = true
		}
		switch r.Label {
		case "OK":
			cOK.Printf("  [OK]         %s   [%d]\n", r.URL, r.Status)
		case "PROTECTED":
			cProtected.Printf("  [PROTECTED]  %s   [%d]\n", r.URL, r.Status)
		case "REDIRECT":
			loc := ""
			if r.Location != "" {
				loc = " -> " + r.Location
			}
			cRedirect.Printf("  [REDIRECT]   %s   [%d]%s\n", r.URL, r.Status, loc)
		}
		results = append(results, r)
	}

	out, _ := os.Create("found.txt")
	for _, r := range results {
		fmt.Fprintln(out, r.URL)
	}
	out.Close()

	fmt.Println()
	cBox.Println(strings.Repeat("═", 46))

	if len(wafsFound) > 0 {
		wafList := make([]string, 0, len(wafsFound))
		for w := range wafsFound {
			wafList = append(wafList, w)
		}
		sort.Strings(wafList)
		cWAF.Printf("  [!] WAF detected: %s\n", strings.Join(wafList, ", "))
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

	fmt.Println()
	cSummary.Println("  ┌─────────────────────────────────────┐")
	cSummary.Printf("  │  OK         : %-22d│\n", okCount)
	cSummary.Printf("  │  Protected  : %-22d│\n", protCount)
	cSummary.Printf("  │  Redirects  : %-22d│\n", redirCount)
	cSummary.Printf("  │  Total      : %-22d│\n", len(results))
	cSummary.Println("  └─────────────────────────────────────┘")
	fmt.Println()
	cInfo.Println("  [+] saved to: found.txt")
}
