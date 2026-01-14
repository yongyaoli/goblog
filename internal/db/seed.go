package db

import (
	"golang.org/x/crypto/bcrypt"
)

func seedAdmin(defaultUser string, defaultPass string) error {
	var count int64
	SQL.Model(&AdminUser{}).Count(&count)
	if count > 0 {
		return nil
	}
	if defaultUser == "" {
		defaultUser = "admin"
	}
	if defaultPass == "" {
		defaultPass = "admin123"
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(defaultPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u := AdminUser{Username: defaultUser, PasswordHash: string(hash), Status: "active"}
	return SQL.Create(&u).Error
}

func seedMenus() error {
	var count int64
	SQL.Model(&Menu{}).Count(&count)
	if count > 0 {
		return nil
	}
	items := []Menu{
		{Title: "文章列表", Path: "/admin/dashboard", Icon: "bi bi-journal-text", Order: 1, Active: true},
		{Title: "新建文章", Path: "/admin/posts/new", Icon: "bi bi-pencil-square", Order: 2, Active: true},
		{Title: "分类管理", Path: "/admin/categories", Icon: "bi bi-folder", Order: 3, Active: true},
		{Title: "标签管理", Path: "/admin/tags", Icon: "bi bi-tags", Order: 4, Active: true},
		{Title: "系列管理", Path: "/admin/series", Icon: "bi bi-collection", Order: 5, Active: true},
		{Title: "评论管理", Path: "/admin/comments", Icon: "bi bi-chat-left-text", Order: 6, Active: true},
		{Title: "浏览记录", Path: "/admin/views", Icon: "bi bi-eye", Order: 7, Active: true},
		{Title: "审计日志", Path: "/admin/audit", Icon: "bi bi-shield-lock", Order: 8, Active: true},
		{Title: "资源管理", Path: "/admin/attachments", Icon: "bi bi-file-earmark-image", Order: 9, Active: true},
		{Title: "菜单管理", Path: "/admin/menus", Icon: "bi bi-list", Order: 10, Active: true},
		{Title: "Redis 监控", Path: "/admin/redis", Icon: "bi bi-database", Order: 11, Active: true},
		{Title: "友情链接", Path: "/admin/links", Icon: "bi bi-link-45deg", Order: 12, Active: true},
		{Title: "站点配置", Path: "/admin/settings", Icon: "bi bi-gear", Order: 13, Active: true},
	}
	for i := range items {
		if err := SQL.Create(&items[i]).Error; err != nil {
			return err
		}
	}
	return nil
}
