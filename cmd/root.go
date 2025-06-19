/*
Copyright © 2021 Michael Eder @edermi / twitter.com/michael_eder_

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/gocolly/colly"
	"github.com/spf13/cobra"
	"golang.org/x/exp/utf8string"
	"golang.org/x/net/html"
)

type skweezConf struct {
	debug        bool
	depth        int
	minLen       int
	maxLen       int
	scope        []string
	output       string
	noFilter     bool
	jsonOutput   bool
	targets      []string
	urlFilter    []*regexp.Regexp
	onlyASCII    bool
	userAgent    string
	headers      []string
	filesystemDir string
}

var validWordRegex = regexp.MustCompile(`^[a-zA-Z0-9]+.*[a-zA-Z0-9]$`)
var stripTrailingSymbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

var rootCmd = &cobra.Command{
	Use:   "skweez [domain1 domain2 domain3]",
	Short: "Sqeezes the words out of websites or from files in a directory",
	Long: `skweez is a fast and easy to use tool that allows you to (recursively)
crawl websites or directories to generate word lists.`,
	Args: cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		paramDebug, err := cmd.LocalFlags().GetBool("debug")
		handleErr(err, false)
		paramDepth, err := cmd.LocalFlags().GetInt("depth")
		handleErr(err, false)
		paramMinLen, err := cmd.LocalFlags().GetInt("min-word-length")
		handleErr(err, false)
		paramMaxLen, err := cmd.LocalFlags().GetInt("max-word-length")
		handleErr(err, false)
		paramScope, err := cmd.LocalFlags().GetStringSlice("scope")
		handleErr(err, false)
		paramURLFilter, err := cmd.LocalFlags().GetString("url-filter")
		handleErr(err, false)
		paramOutput, err := cmd.LocalFlags().GetString("output")
		handleErr(err, false)
		paramNoFilter, err := cmd.LocalFlags().GetBool("no-filter")
		handleErr(err, false)
		paramJsonOutput, err := cmd.LocalFlags().GetBool("json")
		handleErr(err, false)
		paramOnlyASCII, err := cmd.LocalFlags().GetBool("onlyascii")
		handleErr(err, false)
		paramUserAgent, err := cmd.LocalFlags().GetString("user-agent")
		handleErr(err, false)
		paramHeaders, err := cmd.LocalFlags().GetStringArray("with-header")
		handleErr(err, false)
		paramFilesystemDir, err := cmd.LocalFlags().GetString("filesystem")
		handleErr(err, false)

		// At least a domain or -f must be provided
		if len(args) == 0 && paramFilesystemDir == "" {
			fmt.Fprintln(os.Stderr, "error: must supply at least one domain or use the --filesystem/-f flag")
			os.Exit(1)
		}

		sanitizedScope := []string{}
		for _, element := range paramScope {
			sanitizedScope = append(sanitizedScope, extractDomain(element))
		}
		for _, element := range args {
			sanitizedScope = append(sanitizedScope, extractDomain(element))
		}
		if contains(sanitizedScope, "*") {
			sanitizedScope = []string{}
		}
		var preparedFilters []*regexp.Regexp
		if (paramURLFilter != "") && (strings.Trim(" ", paramURLFilter) != "") {
			sanitizedScope = []string{}
			preparedFilters = append(preparedFilters, regexp.MustCompile(paramURLFilter))
		}
		preparedTargets := []string{}
		for _, element := range args {
			preparedTargets = append(preparedTargets, toUri(element))
		}
		config := &skweezConf{
			debug:        paramDebug,
			depth:        paramDepth,
			minLen:       paramMinLen,
			maxLen:       paramMaxLen,
			scope:        sanitizedScope,
			urlFilter:    preparedFilters,
			output:       paramOutput,
			noFilter:     paramNoFilter,
			jsonOutput:   paramJsonOutput,
			targets:      preparedTargets,
			onlyASCII:    paramOnlyASCII,
			userAgent:    paramUserAgent,
			headers:      paramHeaders,
			filesystemDir: paramFilesystemDir,
		}
		run(config)
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.Flags().IntP("depth", "d", 2, "Depth to spider. 0 = unlimited, 1 = Only provided site, 2... = specific depth")
	rootCmd.Flags().IntP("min-word-length", "m", 3, "Minimum word length")
	rootCmd.Flags().IntP("max-word-length", "n", 24, "Maximum word length")
	rootCmd.Flags().StringSlice("scope", []string{}, "Additional site scope, for example subdomains. If not set, only the provided site's domains are in scope. Using * disables scope checks (careful)")
	rootCmd.Flags().StringP("output", "o", "", "When set, write an output file")
	rootCmd.Flags().StringP("url-filter", "u", "", "Filter URL by regexp. .ie: \"(.*\\.)?domain\\.com.*\". Setting this will ignore scope")
	rootCmd.Flags().Bool("no-filter", false, "Do not filter out strings that don't match the regex to check if it looks like a valid word (starts and ends with alphanumeric letter, anything else in between). Also ignores --min-word-length and --max-word-length")
	rootCmd.Flags().Bool("json", false, "Write words + counts in a json file. Requires --output/-o")
	rootCmd.Flags().Bool("debug", false, "Enable Debug output")
	rootCmd.Flags().Bool("onlyascii", false, "When set, filter out non ASCII words")
	rootCmd.Flags().StringP("user-agent", "a", "", "Set custom user-agent")
	rootCmd.Flags().StringArray("with-header", []string{}, "Add a header in the format key:value. May be used multiple times to add more headers, for example --with-header 'foo: abc' --with-header 'bar: xyz' to set the headers foo and bar to their appropriate values")
	rootCmd.Flags().StringP("filesystem", "f", "", "Recursively scan a directory for text files to extract words from.")
}

func handleErr(err error, critical bool) {
	if err != nil {
		if critical {
			panic(err.Error())
		} else {
			fmt.Println(err.Error())
		}
	}
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func initColly(config *skweezConf) *colly.Collector {
	c := colly.NewCollector(
		colly.MaxDepth(config.depth),
		colly.AllowedDomains(config.scope...),
		colly.URLFilters(config.urlFilter...),
	)
	if config.userAgent != "" {
		c.UserAgent = config.userAgent
	}
	c.AllowURLRevisit = false
	return c
}

func registerCallbacks(collector *colly.Collector, config *skweezConf, cache *map[string]int) {
	logger := log.New(os.Stderr, "", log.Ltime)

	collector.OnHTML("a[href]", func(e *colly.HTMLElement) {
		e.Request.Visit(e.Attr("href"))
	})

	collector.OnRequest(func(r *colly.Request) {
		if len(config.headers) > 0 {
			for _, header := range config.headers {
				var headerSplit = strings.SplitN(header, ":", 2)
				if len(headerSplit) > 1 {
					r.Headers.Set(strings.TrimSpace(headerSplit[0]), headerSplit[1])
				}
			}
		}
		if config.debug {
			logger.Println("Visiting", r.URL)
		}
	})
	collector.OnError(func(r *colly.Response, err error) {
		if config.debug {
			logger.Printf("Error: %v\n", err)
			if r != nil {
				logger.Printf("Request URL: %s\n", r.Request.URL)
				logger.Printf("Response Status Code: %d\n", r.StatusCode)
				logger.Printf("Response Body: %s\n", string(r.Body))
			}
		}
	})

	collector.OnResponse(func(r *colly.Response) {
		if config.debug {
			logger.Println("Visited", r.Request.URL)
		}
	})

	collector.OnScraped(func(r *colly.Response) {
		logger.Println("Finished", r.Request.URL)
		extractWords(r.Body, config, cache)
	})
}

func Split(r rune) bool {
	return r == ' ' || r == '\n' || r == '\r'
}

func extractWords(body []byte, config *skweezConf, cache *map[string]int) {
	domDoc := html.NewTokenizer(strings.NewReader(string(body)))
	previousStartTokenTest := domDoc.Token()
outer:
	for {
		tt := domDoc.Next()
		switch {
		case tt == html.ErrorToken:
			break outer
		case tt == html.StartTagToken:
			previousStartTokenTest = domDoc.Token()
		case tt == html.TextToken:
			if previousStartTokenTest.Data == "script" || previousStartTokenTest.Data == "style" {
				continue
			}
			TxtContent := strings.TrimSpace(html.UnescapeString(string(domDoc.Text())))
			if len(TxtContent) > 0 {
				unfilteredWords := strings.FieldsFunc(TxtContent, Split)
				var filteredWords []string
				for _, word := range unfilteredWords {
					candidate := strings.Trim(word, stripTrailingSymbols)
					if config.noFilter {
						filteredWords = append(filteredWords, candidate)
					} else {
						if validWordRegex.MatchString(candidate) {
							if len(candidate) > config.minLen && len(candidate) < config.maxLen && allPrintable(word) {
								if config.onlyASCII {
									candidate := utf8string.NewString(word)
									if !candidate.IsASCII() {
										continue
									}
								}
								filteredWords = append(filteredWords, candidate)
							}
						}
					}
				}
				for _, word := range filteredWords {
					(*cache)[word] += 1
				}
			}
		}
	}
}

// --- Filesystem Scanning Support ---
func isTextFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 512)
	n, _ := f.Read(b)
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return false
		}
	}
	return true
}

func scanFilesystem(dir string, config *skweezConf, cache *map[string]int) {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !isTextFile(path) {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		extractWords(body, config, cache)
		return nil
	})
	handleErr(err, false)
}

func run(config *skweezConf) {
	cache := make(map[string]int)
	if config.filesystemDir != "" {
		scanFilesystem(config.filesystemDir, config, &cache)
	}
	if len(config.targets) > 0 {
		c := initColly(config)
		registerCallbacks(c, config, &cache)
		for _, toVisit := range config.targets {
			c.Visit(toVisit)
		}
	}
	outputResults(config, cache)
}

func outputResults(config *skweezConf, cache map[string]int) {
	if config.jsonOutput {
		jsonString, err := json.Marshal(cache)
		handleErr(err, false)
		if config.output != "" {
			mode := os.O_RDWR | os.O_CREATE
			filedescriptor, err := os.OpenFile(config.output, mode, 0644)
			handleErr(err, true)
			defer filedescriptor.Close()
			filedescriptor.Write(jsonString)
		} else {
			fmt.Println(string(jsonString[:]))
		}
	} else {
		if config.output != "" {
			mode := os.O_RDWR | os.O_CREATE
			filedescriptor, err := os.OpenFile(config.output, mode, 0644)
			handleErr(err, true)
			defer filedescriptor.Close()
			for word := range cache {
				filedescriptor.WriteString(fmt.Sprintf("%s\n", word))
			}
		} else {
			for word := range cache {
				fmt.Printf("%s\n", word)
			}
		}
	}
}

func extractDomain(uri string) string {
	if !strings.Contains(uri, "/") {
		return uri
	} else {
		noProto := strings.TrimPrefix(strings.TrimPrefix(uri, "http://"), "https://")
		return strings.Split(noProto, "/")[0]
	}
}

func toUri(domain string) string {
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return domain
	} else {
		return "https://" + domain
	}
}

func allPrintable(word string) bool {
	for _, rune := range word {
		if !unicode.IsPrint(rune) {
			return false
		}
	}
	return true
}
