package main

import (
	"log"
	"os"
	"strconv"

	"goblog/internal/app"
)

func main() {
	port := 8080
	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			port = p
		}
	}
	if err := app.Run(port); err != nil {
		log.Fatal(err)
	}
}
