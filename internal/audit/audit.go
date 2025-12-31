package audit

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/gin-gonic/gin"
	"goblog/internal/db"
)

func Write(c *gin.Context, action string, resource string, resourceID *uint, metadata map[string]interface{}) {
	var admin string
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
		if len(parts) >= 2 {
			b, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				var m map[string]interface{}
				if json.Unmarshal(b, &m) == nil {
					if v, ok := m["sub"].(string); ok {
						admin = v
					}
				}
			}
		}
	}
	var metaStr string
	if metadata != nil {
		if b, err := json.Marshal(metadata); err == nil {
			metaStr = string(b)
		}
	}
	item := db.AuditLog{
		Admin:      admin,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Path:       c.Request.URL.Path,
		IP:         c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
		Metadata:   metaStr,
	}
	_ = db.SQL.Create(&item).Error
}
