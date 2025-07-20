package main

import (
	"fmt"
	"os"
)

func main() {
	loadEnv()

	url := os.Getenv("SYNOLOGY_HOST")

	response, err := fetchSynologyData(url)
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}
	report, err := generateReport(*response)
	if err != nil {
		fmt.Printf("❌ Error generating report: %v\n", err)
		return
	}

	displayReport(report)

}
