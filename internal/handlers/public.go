package handlers

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"goblog/internal/db"

	"github.com/gin-gonic/gin"
)

type Public struct{}

func NewPublic() *Public { return &Public{} }

func monthDailyCountsJSON() template.JS {
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.Local)
	end := start.AddDate(0, 1, 0)
	type Row struct {
		Day string
		Cnt int
	}
	var rows []Row
	db.SQL.Table("post").
		Select("date_format(published_at, '%Y-%m-%d') as day, count(*) as cnt").
		Where("status = ? AND published_at >= ? AND published_at < ?", "published", start, end).
		Group("day").
		Scan(&rows)
	m := map[string]int{}
	for _, r := range rows {
		m[r.Day] = r.Cnt
	}
	b, _ := json.Marshal(m)
	return template.JS(string(b))
}

func (h *Public) Index(c *gin.Context) {
	page := 1
	size := 20
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 100 {
			size = s
		}
	}
	var categories []db.Category
	var tags []db.Tag
	var total int64
	db.SQL.Model(&db.Post{}).Where("status = ?", "published").Count(&total)
	var posts []db.Post
	db.SQL.Preload("Tags").Preload("Category").
		Where("status = ?", "published").
		Order("published_at desc").
		Limit(size).
		Offset((page - 1) * size).
		Find(&posts)
	db.SQL.Order("title asc").Find(&categories)
	db.SQL.Order("name asc").Find(&tags)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	prev := page - 1
	if prev < 1 {
		prev = 1
	}
	next := page + 1
	if next > pages {
		next = pages
	}
	c.HTML(http.StatusOK, "public/index.html", gin.H{
		"posts":           posts,
		"categories":      categories,
		"tags":            tags,
		"page":            page,
		"pages":           pages,
		"prevPage":        prev,
		"nextPage":        next,
		"size":            size,
		"total":           total,
		"dailyCountsJSON": monthDailyCountsJSON(),
	})
}

func (h *Public) Post(c *gin.Context) {
	slug := c.Param("slug")
	var p db.Post
	if err := db.SQL.Preload("Tags").Preload("Category").Where("slug = ?", slug).First(&p).Error; err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	db.SQL.Model(&p).UpdateColumn("views", gorm.Expr("views + 1"))
	db.SQL.Create(&db.ViewLog{
		PostID:    p.ID,
		IP:        c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Path:      c.Request.URL.Path,
	})
	var comments []db.Comment
	db.SQL.Where("post_id = ? AND approved = ?", p.ID, true).Order("created_at asc").Find(&comments)
	var categories []db.Category
	var tags []db.Tag
	db.SQL.Order("title asc").Find(&categories)
	db.SQL.Order("name asc").Find(&tags)
	c.HTML(http.StatusOK, "public/post.html", gin.H{
		"post":            p,
		"comments":        comments,
		"htmlContent":     template.HTML(p.Content),
		"categories":      categories,
		"tags":            tags,
		"dailyCountsJSON": monthDailyCountsJSON(),
	})
}

type commentReq struct {
	AuthorName  string `form:"author_name" json:"author_name"`
	AuthorEmail string `form:"author_email" json:"author_email"`
	Content     string `form:"content" json:"content"`
	ParentID    *uint  `form:"parent_id" json:"parent_id"`
}

func (h *Public) CreateComment(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	var req commentReq
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请填写评论内容"})
		return
	}
	email := strings.TrimSpace(req.AuthorEmail)
	re := regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	if !re.MatchString(email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入有效的邮箱"})
		return
	}
	ip := c.ClientIP()
	// 限流：同一IP对同一文章10分钟内只能评论一次
	if db.Redis != nil {
		key := "comment_rate:" + ip + ":" + idStr
		ok, err := db.Redis.SetNX(context.Background(), key, "1", 10*time.Minute).Result()
		if err != nil {
			var cnt int64
			since := time.Now().Add(-10 * time.Minute)
			db.SQL.Model(&db.Comment{}).Where("post_id = ? AND ip = ? AND created_at > ?", id, ip, since).Count(&cnt)
			if cnt > 0 {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "同一IP对同一文章10分钟内只能评论一次"})
				return
			}
		} else if !ok {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "同一IP对同一文章10分钟内只能评论一次"})
			return
		}
	} else {
		var cnt int64
		since := time.Now().Add(-10 * time.Minute)
		db.SQL.Model(&db.Comment{}).Where("post_id = ? AND ip = ? AND created_at > ?", id, ip, since).Count(&cnt)
		if cnt > 0 {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "同一IP对同一文章10分钟内只能评论一次"})
			return
		}
	}
	comment := db.Comment{
		PostID:      uint(id),
		AuthorName:  req.AuthorName,
		AuthorEmail: req.AuthorEmail,
		Content:     req.Content,
		ParentID:    req.ParentID,
		Approved:    false,
		IP:          ip,
	}
	if err := db.SQL.Create(&comment).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Public) Archive(c *gin.Context) {
	type Item struct {
		ID    uint
		Title string
		Slug  string
		Month string
	}
	var items []Item
	db.SQL.Model(&db.Post{}).
		Select("id, title, slug, date_format(published_at, '%Y-%m') as month").
		Where("status = ? AND published_at IS NOT NULL", "published").
		Order("published_at desc").Scan(&items)
	var categories []db.Category
	var tags []db.Tag
	db.SQL.Order("title asc").Find(&categories)
	db.SQL.Order("name asc").Find(&tags)
	c.HTML(http.StatusOK, "public/archive.html", gin.H{
		"items":           items,
		"categories":      categories,
		"tags":            tags,
		"dailyCountsJSON": monthDailyCountsJSON(),
	})
}

func (h *Public) Series(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	var s db.Series
	if err := db.SQL.First(&s, id).Error; err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	var posts []db.Post
	db.SQL.Where("series_id = ? AND status = ?", s.ID, "published").Order("published_at desc").Find(&posts)
	var categories []db.Category
	var tags []db.Tag
	db.SQL.Order("title asc").Find(&categories)
	db.SQL.Order("name asc").Find(&tags)
	c.HTML(http.StatusOK, "public/series.html", gin.H{
		"series":          s,
		"posts":           posts,
		"categories":      categories,
		"tags":            tags,
		"dailyCountsJSON": monthDailyCountsJSON(),
	})
}

func (h *Public) TagPosts(c *gin.Context) {
	name := c.Param("name")
	var tag db.Tag
	if err := db.SQL.Where("name = ?", name).First(&tag).Error; err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	page := 1
	size := 10
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 100 {
			size = s
		}
	}
	var total int64
	db.SQL.Table("post").
		Joins("JOIN post_tag pt ON pt.post_id = post.id").
		Where("pt.tag_id = ? AND post.status = ?", tag.ID, "published").
		Count(&total)
	var posts []db.Post
	db.SQL.Preload("Category").
		Joins("JOIN post_tag pt ON pt.post_id = post.id").
		Where("pt.tag_id = ? AND post.status = ?", tag.ID, "published").
		Order("published_at desc").
		Limit(size).
		Offset((page - 1) * size).
		Find(&posts)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	prev := page - 1
	if prev < 1 {
		prev = 1
	}
	next := page + 1
	if next > pages {
		next = pages
	}
	var categories []db.Category
	var tags []db.Tag
	db.SQL.Order("title asc").Find(&categories)
	db.SQL.Order("name asc").Find(&tags)
	c.HTML(http.StatusOK, "public/tag.html", gin.H{
		"tag":             tag,
		"posts":           posts,
		"page":            page,
		"pages":           pages,
		"prevPage":        prev,
		"nextPage":        next,
		"total":           total,
		"size":            size,
		"categories":      categories,
		"tags":            tags,
		"dailyCountsJSON": monthDailyCountsJSON(),
	})
}

func (h *Public) CategoryPosts(c *gin.Context) {
	slug := c.Param("name")
	var cat db.Category
	if err := db.SQL.Where("slug = ?", slug).First(&cat).Error; err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	var posts []db.Post
	db.SQL.Where("category_id = ? AND status = ?", cat.ID, "published").Order("published_at desc").Find(&posts)
	var categories []db.Category
	var tags []db.Tag
	db.SQL.Order("title asc").Find(&categories)
	db.SQL.Order("name asc").Find(&tags)
	c.HTML(http.StatusOK, "public/category.html", gin.H{
		"category":        cat,
		"posts":           posts,
		"categories":      categories,
		"tags":            tags,
		"dailyCountsJSON": monthDailyCountsJSON(),
	})
}

func (h *Public) RSS(c *gin.Context) {
	var posts []db.Post
	db.SQL.Where("status = ?", "published").Order("published_at desc").Limit(50).Find(&posts)
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	base := scheme + "://" + c.Request.Host
	rss := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<title>我的博客</title>
<link>` + base + `</link>
<description>RSS Feed</description>`
	for _, p := range posts {
		link := base + "/post/" + p.Slug
		pub := ""
		if p.PublishedAt != nil {
			pub = p.PublishedAt.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
		}
		rss += "<item><title><![CDATA[" + p.Title + "]]></title><link>" + link + "</link><description><![CDATA[" + p.Summary + "]]></description>"
		if pub != "" {
			rss += "<pubDate>" + pub + "</pubDate>"
		}
		rss += "</item>"
	}
	rss += "</channel></rss>"
	c.Header("Content-Type", "application/rss+xml; charset=utf-8")
	c.String(http.StatusOK, rss)
}

func (h *Public) Sitemap(c *gin.Context) {
	var posts []db.Post
	db.SQL.Where("status = ?", "published").Order("published_at desc").Find(&posts)
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	base := scheme + "://" + c.Request.Host
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>` + base + `</loc></url>`
	for _, p := range posts {
		link := base + "/post/" + p.Slug
		xml += "<url><loc>" + link + "</loc></url>"
	}
	xml += "</urlset>"
	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.String(http.StatusOK, xml)
}
