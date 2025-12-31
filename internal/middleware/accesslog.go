package middleware

import (
	"strings"

	"goblog/internal/db"

	"github.com/gin-gonic/gin"
)

func AccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api") {
			c.Next()
			return
		}
		if strings.HasPrefix(c.Request.URL.Path, "/static/") {
			c.Next()
			return
		}
		if c.Request.URL.Path == "/favicon.ico" {
			c.Next()
			return
		}
		db.SQL.Create(&db.ViewLog{
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Path:      c.Request.URL.Path,
		})
		c.Next()
	}
}
