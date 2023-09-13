package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	vulnerableCount    int
	notVulnerableCount int
)

func checkVulnerability(url string, wg *sync.WaitGroup, resultsFile *os.File) {
	defer wg.Done()
	client := &http.Client{}
	paths := []string{"wp-head.php", "radio.php", "simple.php", "cong.php", "repeater.php"}

	for _, path := range paths {
		fullURL := url + "/" + path
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			fmt.Println(err)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			continue
		}

		if strings.Contains(string(body), "-rw-r--r--") || strings.Contains(string(body), "BlackDragon") {
			vulnerableCount++
			fmt.Printf("[*] >> %s = %s\n", fullURL, fullURL)
			resultsFile.WriteString(fullURL + "\n")
		} else {
			notVulnerableCount++
			fmt.Printf("[*] %s >>> [Not Vuln]\n", fullURL)
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano()) // Initialize the random seed

	fmt.Println(`
 _______     _     _                            _  _
(_______)   (_)   (_)                          | |(_)       _   
 _  _  _  ____ ___      _____ _   _ ____   ___ | | _  ___ _| |_ 
| ||_|| |/ ___)   |    | ___ ( \ / )  _ \ / _ \| || |/ _ (_   _)
| |   | | |_ / / \ \   | ____|) X (| |_| | |_| | || | |_| || |_ 
|_|   |_|_(_)_|   |_|  |_____|_/ \_)  __/ \___/ \_)_|\___/  \__)
                                   | |
 MR-X tg- https://t.me/jackleet    '"'
`)

	fmt.Print("Enter the path to the text file containing website domains: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	inputFile := scanner.Text()
	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	resultsFile, err := os.Create("results.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resultsFile.Close()

	var domains []string
	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		domains = append(domains, strings.TrimSpace(scanner.Text()))
	}

	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go checkVulnerability(domain, &wg, resultsFile)
	}
	wg.Wait()

	fmt.Printf("Vulnerable: %d, Not Vulnerable: %d\n", vulnerableCount, notVulnerableCount)
}
