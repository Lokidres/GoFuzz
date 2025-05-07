package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	toolName    = "GoFuzz"
	toolVersion = "2.1.2"
	toolAuthor  = "lokidres"
)

type ScanConfig struct {
	target      string
	subdomains  string
	directories string
	threads     int
	timeout     int
	output      string
	verbose     bool
	recursive   bool
	showHelp    bool
	showVersion bool
	filters     string
}

type ScanResult struct {
	url      string
	status   int
	size     int64
	redirect string
}

var (
	httpClient *http.Client
)

func main() {
	config := ScanConfig{}

	flag.StringVar(&config.target, "u", "", "Target URL to scan")
	flag.StringVar(&config.subdomains, "s", "", "Subdomain wordlist file")
	flag.StringVar(&config.directories, "d", "", "Directory wordlist file")
	flag.IntVar(&config.threads, "t", 10, "Number of concurrent threads")
	flag.IntVar(&config.timeout, "timeout", 10, "Request timeout in seconds")
	flag.StringVar(&config.output, "o", "", "Output file to save results")
	flag.BoolVar(&config.verbose, "v", false, "Verbose output")
	flag.BoolVar(&config.recursive, "r", false, "Enable recursive scanning")
	flag.BoolVar(&config.showHelp, "h", false, "Show help menu")
	flag.BoolVar(&config.showVersion, "version", false, "Show version info")
	flag.StringVar(&config.filters, "f", "", "Filter by status codes (comma-separated, e.g. 200,302)")

	flag.Usage = func() {
		fmt.Printf("%s v%s by %s\n\n", toolName, toolVersion, toolAuthor)
		fmt.Println("Usage:")
		fmt.Println("  gofuzz -u <target> -s <subdomains> -d <directories> [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if config.showVersion {
		fmt.Printf("%s v%s by %s\n", toolName, toolVersion, toolAuthor)
		return
	}

	if config.showHelp {
		flag.Usage()
		return
	}

	if config.target == "" {
		log.Fatal("Target URL is required (use -u flag)")
	}

	if config.subdomains == "" && config.directories == "" {
		log.Fatal("At least one wordlist is required (use -s or -d flags)")
	}

	httpClient = &http.Client{
		Timeout: time.Duration(config.timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	fmt.Printf("________  ________  ________ ___  ___  ________  ________\n")
	fmt.Printf("|\\   ____\\|\\   __  \\|\\  _____\\\\  \\|\\  \\|\\_____  \\|\\_____  \\ \n")
	fmt.Printf("\\ \\  \\___|\\ \\  \\|\\  \\ \\  \\_/\\ \\  \\\\  \\\\|___/  /|\\|___/  /| \n")
	fmt.Printf(" \\ \\  \\  __\\ \\  \\\\  \\ \\   __\\\\ \\  \\\\  \\   /  / /    /  / / \n")
	fmt.Printf("  \\ \\  \\|\\  \\ \\  \\\\  \\ \\  \\_| \\ \\  \\\\  \\ /  /_/__  /  /_/__ \n")
	fmt.Printf("   \\ \\_______\\ \\_______\\ \\__\\   \\ \\_______\\\\________\\\\________\\\n")
	fmt.Printf("    \\|_______|\\|_______|\\|__|    \\|_______|\\|_______|\\|_______|\n")
	fmt.Printf("                      %s v%s by %s\n\n", toolName, toolVersion, toolAuthor)

	results := make(chan ScanResult)
	done := make(chan struct{})
	visitedURLs := make(map[string]bool)

	allowedStatusCodes := parseFilterCodes(config.filters)
	if config.verbose && len(allowedStatusCodes) > 0 {
		var codes []string
		for code := range allowedStatusCodes {
			codes = append(codes, strconv.Itoa(code))
		}
		log.Printf("Filtering for status codes: %s", strings.Join(codes, ", "))
	}

	var outputWriter *os.File
	if config.output != "" {
		var err error
		outputWriter, err = os.Create(config.output)
		if err != nil {
			log.Fatalf("Failed to create output file: %v", err)
		}
		defer outputWriter.Close()
	}

	go func() {
		for result := range results {
			if _, visited := visitedURLs[result.url]; visited {
				continue
			}
			visitedURLs[result.url] = true

			if config.verbose {
				log.Printf("Processing result: URL=%s, Status=%d", result.url, result.status)
			}

			if len(allowedStatusCodes) > 0 && !allowedStatusCodes[result.status] {
				if config.verbose {
					log.Printf("Filtered out %s with status %d (not in filter list)",
						result.url, result.status)
				}
				continue
			}

			outputLine := fmt.Sprintf("%s [%d] (Size: %d)", result.url, result.status, result.size)
			if result.redirect != "" {
				outputLine += fmt.Sprintf(" -> %s", result.redirect)
			}
			fmt.Println(outputLine)

			if outputWriter != nil {
				if _, err := outputWriter.WriteString(outputLine + "\n"); err != nil && config.verbose {
					log.Printf("Error writing to output file: %v", err)
				}
			}
		}
		close(done)
	}()

	var wg sync.WaitGroup
	sem := make(chan struct{}, config.threads)

	if config.subdomains != "" {
		subdomainList, err := loadWordlist(config.subdomains)
		if err != nil {
			log.Fatalf("Error loading subdomains: %v", err)
		}

		for _, subdomain := range subdomainList {
			wg.Add(1)
			sem <- struct{}{}
			go func(sd string) {
				defer wg.Done()
				defer func() { <-sem }()
				scanTarget(buildSubdomainUrl(config.target, sd), results, config.verbose, true)
			}(subdomain)
		}
	}

	if config.directories != "" {
		directoryList, err := loadWordlist(config.directories)
		if err != nil {
			log.Fatalf("Error loading directories: %v", err)
		}

		for _, directory := range directoryList {
			wg.Add(1)
			sem <- struct{}{}
			go func(dir string) {
				defer wg.Done()
				defer func() { <-sem }()
				scanTarget(buildDirectoryUrl(config.target, dir), results, config.verbose, false)
			}(directory)
		}
	}

	wg.Wait()
	close(results)
	<-done
}

func parseFilterCodes(filterStr string) map[int]bool {
	result := make(map[int]bool)
	if filterStr == "" {
		return result
	}

	for _, codeStr := range strings.Split(filterStr, ",") {
		codeStr = strings.TrimSpace(codeStr)
		if code, err := strconv.Atoi(codeStr); err == nil {
			result[code] = true
		}
	}

	return result
}

func loadWordlist(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func buildSubdomainUrl(baseUrl, subdomain string) string {
	target, err := url.Parse(baseUrl)
	if err != nil {
		return fmt.Sprintf("http://%s.%s", subdomain, baseUrl)
	}
	return fmt.Sprintf("%s://%s.%s", target.Scheme, subdomain, target.Host)
}

func buildDirectoryUrl(baseUrl, directory string) string {
	return fmt.Sprintf("%s/%s", strings.TrimSuffix(baseUrl, "/"), strings.TrimPrefix(directory, "/"))
}

func scanTarget(targetUrl string, results chan<- ScanResult, verbose bool, isSubdomain bool) {
	if strings.Contains(targetUrl, "#") {
		return
	}

	req, err := http.NewRequest("GET", targetUrl, nil)
	if err != nil {
		if verbose {
			log.Printf("Error creating request for %s: %v", targetUrl, err)
		}
		return
	}

	req.Header.Set("User-Agent", "GoFuzz/"+toolVersion)

	if verbose {
		log.Printf("Sending request to: %s", targetUrl)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if verbose {
			log.Printf("Error scanning %s: %v", targetUrl, err)
		}
		return
	}
	defer resp.Body.Close()

	if verbose {
		log.Printf("Response from %s: Status=%d, Headers=%v",
			targetUrl, resp.StatusCode, resp.Header)
	}

	status := resp.StatusCode
	redirect := ""

	if status == http.StatusMovedPermanently || status == http.StatusFound ||
		status == http.StatusSeeOther || status == http.StatusTemporaryRedirect ||
		status == http.StatusPermanentRedirect {
		redirect = resp.Header.Get("Location")
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	size := int64(len(bodyBytes))

	if isSubdomain && (status < 200 || status >= 400) {
		if verbose {
			log.Printf("Subdomain %s returned non-successful status: %d", targetUrl, status)
		}
		return
	}

	if verbose {
		log.Printf("Sending result for %s: Status=%d, Size=%d", targetUrl, status, size)
	}

	results <- ScanResult{
		url:      targetUrl,
		status:   status,
		size:     size,
		redirect: redirect,
	}
}
