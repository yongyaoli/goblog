package main

import (
	"log"
	"os"
	"strconv"

	"goblog/internal/app"
)

// @title GoBlog API
// @version 1.0
// @description GoBlog 管理后台与前台 API 文档
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
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
