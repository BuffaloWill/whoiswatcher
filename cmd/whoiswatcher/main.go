package main

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var rootCmd = &cobra.Command{
	Use:  "whoiswatcher",
	Long: `Get alerted on domains of interest.`,
}

var socksproxy string
var domain string
var filePath string
var watchlistPath string
var watchlist WatchList
var verbose bool
var errorMessages bool
var timeoutLookup int
var outputField string
var rateLimited []string
var lock sync.Mutex
var threads int
var strikes []string
var jsoni string
var sleeper int
var nrdDirectory string

type WatchList []Condition

type Combo struct {
	Key   string `yaml:"key"` // email, name, organization, phone
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

type Condition struct {
	Key   string  `yaml:"key"` // email, name, organization, phone
	Type  string  `yaml:"type"`
	Value string  `yaml:"value"`
	Combo []Combo `yaml:"combo,omitempty"`
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&filePath, "file", "f", "", "Path to a file containing domains")
	rootCmd.PersistentFlags().StringVarP(&watchlistPath, "watchlist", "w", "", "Path to a file containing the watchlist as yaml")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Print out all whois lookups")
	rootCmd.PersistentFlags().BoolVarP(&errorMessages, "error", "e", false, "Only print if there is an error.")
	rootCmd.PersistentFlags().StringVarP(&outputField, "outputField", "u", "", "Output a single field from the result: email, phone, name, or organization")
	rootCmd.PersistentFlags().StringVarP(&socksproxy, "proxy", "p", "", "SOCKS5 Proxy to use")
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "t", 10, "Number of threads")
	rootCmd.PersistentFlags().StringVarP(&jsoni, "jsoninput", "j", "", "Run against a previously imported json file")
	rootCmd.PersistentFlags().IntVarP(&sleeper, "sleep", "s", 10, "Seconds to sleep between requests when rate limited.")
	rootCmd.PersistentFlags().StringVarP(&nrdDirectory, "nrd", "x", "", "Use directory as input. Download yesterdays newly registered domains and write to the provided directory.")

	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		if nrdDirectory != "" {
			yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
			log.Printf("[+] Downloading yesterday's Newly Registered Domains and writing to %+v", nrdDirectory)
			downloadNRD(yesterday, nrdDirectory)
			return
		}

		// If a user doesn't set a watchlist, automatically output the result
		if watchlistPath == "" {
			verbose = true
		} else {
			processWatchList(watchlistPath)
		}

		if jsoni != "" {
			if watchlistPath == "" {
				log.Fatalf("JSON Input requires a watchlist")
			}

			result := whoisparser.WhoisInfo{}
			file, err := os.Open(jsoni)
			if err != nil {
				fmt.Println(os.Stderr, "Error opening json input file: %v", err)
				os.Exit(1)
			}
			defer file.Close()

			jsoninput := bufio.NewScanner(file)
			for jsoninput.Scan() {
				line := jsoninput.Text()
				err := json.Unmarshal([]byte(line), &result)
				if err != nil {
					//fmt.Fprintf(os.Stderr, "Error unmarshaling line in JSON file: %v\n", err)
					continue
				}

				if verbose == true {
					fmt.Println(line)
					resultJSON, err := json.MarshalIndent(result, "", "  ")
					if err != nil {
						fmt.Println(os.Stderr, "Error marshaling result to JSON: %v", err)
						continue
					}

					// todo - flip this back or delete
					if false {
						fmt.Println(string(resultJSON))
					}

				}

				if result.Registrant != nil {
					processResultWatchlist(result)
				}
			}
			return
		}

		if filePath != "" {
			processFile(filePath)
		} else {
			processStdin()
		}

		// Process anything left over
		if len(rateLimited) > 0 {
			processRateLimited()
		}
	}
}

func processWatchList(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading YAML file: %v\n", err)
		os.Exit(1)
	}

	err = yaml.Unmarshal(data, &watchlist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error unmarshaling YAML file: %v\n", err)
		os.Exit(1)
	}
}

func processFile(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	domainChan := make(chan string)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			//defer wg.Done()
			for domain := range domainChan {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()

				go processDomain(domain)

				select {
				case <-ctx.Done():
					if ctx.Err() == context.DeadlineExceeded {
						fmt.Println("{\"error\":\"Operation timed out - " + domain + " \"}")
					}
				}
			}
		}()
	}

	for scanner.Scan() {
		domain := scanner.Text()
		domainChan <- domain
	}

	close(domainChan)
	wg.Wait()
}

func processRateLimited() {
	fmt.Printf("{\"message\":\"Processing a total of %v rate limited domains, sleeping for %v seconds\"}\n", len(rateLimited), sleeper)
	time.Sleep(time.Duration(sleeper) * time.Second)

	for {
		lock.Lock()
		if len(rateLimited) == 0 {
			lock.Unlock()
			break
		}
		processDomain(rateLimited[0])
		rateLimited = rateLimited[1:]
		lock.Unlock()
		rand.Seed(time.Now().UnixNano())
		randomNumber := rand.Intn(10)
		if randomNumber == 0 {
			fmt.Printf("{\"message\":\"Processing a total of %v rate limited domains, sleeping for %v seconds\"}\n", len(rateLimited), sleeper)
			time.Sleep(time.Duration(sleeper) * time.Second)
		}
	}
}

func processStdin() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := scanner.Text()
		processDomain(domain)
	}
}

func printJson(result whoisparser.WhoisInfo) {
	jsonData, err := json.Marshal(result)
	if err != nil {
		log.Fatalf("Error occurred during serialization: %v", err)
	}
	fmt.Println(string(jsonData))
}

func checkForMatch(inputs []string, conditionType, value string) bool {
	for _, x := range inputs {
		input := strings.ToLower(x)
		value = strings.ToLower(value)

		switch conditionType {
		case "contains":
			if strings.Contains(input, value) {

				return true
			}
		case "matches":
			if input == value {
				return true
			}
		}
	}
	return false
}

func processDomain(domain string) {
	result := whoisparser.WhoisInfo{}

	c := whois.NewClient()
	c.SetTimeout(time.Second * 4)
	if socksproxy != "" {
		dialer, err := proxy.SOCKS5("tcp", socksproxy, nil, proxy.Direct)
		if err != nil {
			log.Fatal(`{"error":"error creating dialer, ` + err.Error() + `"}`)
		}
		c.SetDialer(dialer)
	}
	whois_raw, err := c.Whois(domain)
	if err != nil {
		time.Sleep(time.Second * 1)
		whois_raw, err = c.Whois(domain)
		if err != nil {
			fmt.Println(`{"error":"Error occurred during whois lookup, ` + err.Error() + `"}`)
		}
	}

	result, err = whoisparser.Parse(whois_raw)
	if err != nil {
		fmt.Println(`{"error":"Error during check with:` + domain + `" - "` + err.Error() + `"}`)
		return
	}

	if verbose == true {
		printJson(result)
	}
	if len(result.Domain.Status) > 0 && result.Domain.Status[0] == "redemptionperiod" {
		// Redemptionperiod will never return a result, exit to not block on this domain.
		return
	}

	// If there is no registrant, we /maybe/ got rate limited. Explore this more.
	if result.Registrant == nil {
		//fmt.Println("Rate Limited: ", domain)
		//fmt.Printf("%+v", result)
		// TODO - whois library has a rate limiting boolean check, this should be used first
		rateLimited = append(rateLimited, domain)
		return
	}

	if strings.Contains(result.Registrant.Name, "REDACTED") {
		// todo - do something here
	}

	// Check if technical, administrative, and billing are set -- if not, blank them out.
	if result.Technical == nil {
		result.Technical = &whoisparser.Contact{}
	}
	if result.Administrative == nil {
		result.Administrative = &whoisparser.Contact{}
	}
	if result.Billing == nil {
		result.Billing = &whoisparser.Contact{}
	}
	if result.Registrant == nil {
		result.Registrant = &whoisparser.Contact{}
	}

	// This feature allows a user to output a single field from a record.
	if outputField != "" {
		fields := strings.Split(outputField, ",")
		for _, value := range fields {
			if value == "email" {
				fmt.Println("Registrar Email:" + result.Registrant.Email)
				fmt.Println("Administrative Email:" + result.Administrative.Email)
				fmt.Println("Technical Email:" + result.Technical.Email)
			}
			if value == "phone" {
				fmt.Println("Registrar Phone:" + result.Registrant.Phone)
				fmt.Println("Administrative Phone:" + result.Administrative.Phone)
				fmt.Println("Technical Phone:" + result.Technical.Phone)
			}
			if value == "organization" {
				fmt.Println("Registrant Organization:" + result.Registrant.Organization)
				fmt.Println("Administrative Organization:" + result.Administrative.Organization)
				fmt.Println("Technical Organization:" + result.Technical.Organization)
			}
			if value == "name" {
				fmt.Println("Registrar Name:" + result.Registrant.Name)
				fmt.Println("Administrative Name:" + result.Administrative.Name)
				fmt.Println("Technical Name:" + result.Technical.Name)
			}
		}
	}
	processResultWatchlist(result)
}

func processResultWatchlist(result whoisparser.WhoisInfo) {
	// Check if technical, administrative, and billing are set if not blank them out.
	if result.Technical == nil {
		result.Technical = &whoisparser.Contact{}
	}
	if result.Administrative == nil {
		result.Administrative = &whoisparser.Contact{}
	}
	if result.Billing == nil {
		result.Billing = &whoisparser.Contact{}
	}
	if result.Registrant == nil {
		result.Registrant = &whoisparser.Contact{}
	}

	emailsToCheck := []string{
		result.Registrant.Email,
		result.Technical.Email,
		result.Administrative.Email,
		result.Billing.Email,
	}

	namesToCheck := []string{
		result.Registrant.Name,
		result.Technical.Name,
		result.Administrative.Name,
		result.Billing.Name,
	}

	organizationToCheck := []string{
		result.Registrant.Organization,
		result.Technical.Organization,
		result.Administrative.Organization,
		result.Billing.Organization,
	}

	phoneToCheck := []string{
		result.Registrant.Phone,
		result.Technical.Phone,
		result.Administrative.Phone,
		result.Billing.Phone,
	}

	//registrarToCheck := result.Registrar.Name
	for _, condition := range watchlist {
		if len(condition.Combo) > 0 {
			// Todo - This code smells bad and needs to be refactored. checkForMatch could return true or false?
			pass1 := false
			combo1 := condition.Combo[0]

			if combo1.Key == "email" {
				if checkForMatch(emailsToCheck, combo1.Type, combo1.Value) {
					pass1 = true
				}
			}

			if combo1.Key == "name" {
				if checkForMatch(namesToCheck, combo1.Type, combo1.Value) {
					pass1 = true
				}
			}

			if combo1.Key == "organization" {
				if checkForMatch(organizationToCheck, combo1.Type, combo1.Value) {
					pass1 = true
				}
			}

			if combo1.Key == "phone" {
				if checkForMatch(phoneToCheck, combo1.Type, combo1.Value) {
					pass1 = true
				}
			}

			if combo1.Key == "domain" {
				sd := []string{domain}
				if checkForMatch(sd, combo1.Type, combo1.Value) {
					pass1 = true
				}
			}

			if combo1.Key == "registrar" {
				sd := []string{result.Registrar.Name}
				if checkForMatch(sd, combo1.Type, combo1.Value) {
					pass1 = true
				}
			}

			// Exit if the first thing does not match
			if pass1 == false {
				return
			}

			combo2 := condition.Combo[1]

			if combo2.Key == "email" {
				if checkForMatch(emailsToCheck, combo2.Type, combo2.Value) {
					fmt.Printf("Combo Match: %v \n", condition.Combo)
					printJson(result)
					return
				}
			}

			if combo2.Key == "name" {
				if checkForMatch(namesToCheck, combo2.Type, combo2.Value) {
					fmt.Printf("Combo Match: %v \n", condition.Combo)
					printJson(result)
					return
				}
			}

			if combo2.Key == "organization" {
				if checkForMatch(organizationToCheck, combo2.Type, combo2.Value) {
					fmt.Printf("Combo Match: %v \n", condition.Combo)
					printJson(result)
					return
				}
			}

			if combo2.Key == "phone" {
				if checkForMatch(phoneToCheck, combo2.Type, combo2.Value) {
					fmt.Printf("Combo Match: %v \n", condition.Combo)
					printJson(result)
					break
				}
			}

			if combo2.Key == "domain" {
				sd := []string{domain}
				if checkForMatch(sd, combo2.Type, combo2.Value) {
					fmt.Printf("Combo Match: %v \n", condition.Combo)
					printJson(result)
					break
				}
			}

			if combo2.Key == "registrar" {
				sd := []string{result.Registrar.Name}
				if checkForMatch(sd, combo2.Type, combo2.Value) {
					fmt.Printf("Combo Match: %v \n", condition.Combo)
					printJson(result)
					break
				}
			}
		}

		if condition.Key == "email" {
			if checkForMatch(emailsToCheck, condition.Type, condition.Value) {
				fmt.Printf("Match on any email: %v - %v - %v \n", emailsToCheck, condition.Type, condition.Value)
				printJson(result)
				return
			}
		}

		if condition.Key == "name" {
			if checkForMatch(namesToCheck, condition.Type, condition.Value) {
				fmt.Printf("Match on any name: %v - %v - %v \n", namesToCheck, condition.Type, condition.Value)
				printJson(result)
				return
			}
		}

		if condition.Key == "organization" {
			if checkForMatch(organizationToCheck, condition.Type, condition.Value) {
				fmt.Printf("Match on any organization: %v - %v - %v \n", organizationToCheck, condition.Type, condition.Value)
				printJson(result)
				return
			}
		}

		if condition.Key == "phone" {
			if checkForMatch(phoneToCheck, condition.Type, condition.Value) {
				fmt.Printf("Match on any phone: %v - %v - %v \n", phoneToCheck, condition.Type, condition.Value)
				printJson(result)
				break
			}
		}
	}
}

func downloadNRD(date, dir string) {
	zipFile := filepath.Join(dir, date+".zip")
	if _, err := os.Stat(zipFile); os.IsNotExist(err) {
		b64 := base64.StdEncoding.EncodeToString([]byte(date + ".zip"))
		nrdZip := fmt.Sprintf("https://www.whoisds.com//whois-database/newly-registered-domains/%s/nrd", b64)

		resp, err := http.Get(nrdZip)
		if err != nil || resp.StatusCode != http.StatusOK {
			fmt.Printf("File %s.zip does not exist on the remote server.\n", date)
			return
		}
		defer resp.Body.Close()

		out, err := os.Create(zipFile)
		if err != nil {
			fmt.Printf("Error creating file: %v\n", err)
			return
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			fmt.Printf("Error downloading file: %v\n", err)
			return
		}

		r, err := zip.OpenReader(zipFile)
		if err != nil {
			fmt.Printf("Error opening zip file: %v\n", err)
			return
		}
		defer r.Close()

		for _, f := range r.File {
			rc, err := f.Open()
			if err != nil {
				fmt.Printf("Error opening file in zip: %v\n", err)
				return
			}
			defer rc.Close()

			outPath := filepath.Join(dir, date+".txt")
			outFile, err := os.Create(outPath)
			if err != nil {
				fmt.Printf("Error creating extracted file: %v\n", err)
				return
			}
			defer outFile.Close()

			_, err = io.Copy(outFile, rc)
			if err != nil {
				fmt.Printf("Error extracting file: %v\n", err)
				return
			}
			log.Println("[+] Wrote to ", outPath)
		}
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
