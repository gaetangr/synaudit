package utils

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func LoadEnv() error {
	file, err := os.Open(".env")
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			value = strings.Trim(value, `"'`)
			os.Setenv(key, value)
		}
	}
	return scanner.Err()
}

func ExtractHost(urlString string) (string, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		fmt.Printf("❌ Error parsing URL: %v\n", err)
		return "", err
	}
	return parsedURL.Hostname(), nil
}
