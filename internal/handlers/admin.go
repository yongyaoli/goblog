package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"goblog/internal/audit"
	"goblog/internal/config"
	"goblog/internal/db"
	"goblog/internal/logger"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Admin struct {
	secret string
}

func NewAdmin(secret string) *Admin {
	return &Admin{secret: secret}
}

func (a *Admin) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/login.html", gin.H{"active": "login", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

func (a *Admin) DashboardPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/dashboard.html", gin.H{"active": "dashboard", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

func (a *Admin) CategoriesPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/categories.html", gin.H{"active": "categories", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

func (a *Admin) TagsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/tags.html", gin.H{"active": "tags", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

func (a *Admin) SeriesPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/series.html", gin.H{"active": "series", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

func (a *Admin) CommentsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/comments.html", gin.H{"active": "comments", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

func (a *Admin) ViewsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/views.html", gin.H{"active": "views", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

func (a *Admin) PostEditPage(c *gin.Context) {
	id := c.Param("id")
	var post db.Post
	if id != "" {
		_ = db.SQL.Preload("Tags").First(&post, id).Error
	}
	var tags []db.Tag
	db.SQL.Order("name asc").Find(&tags)
	var series []db.Series
	db.SQL.Order("name asc").Find(&series)
	var categories []db.Category
	db.SQL.Order("title asc").Find(&categories)
	type catOpt struct {
		ID       uint
		Label    string
		Selected bool
	}
	type seriesOpt struct {
		ID       uint
		Name     string
		Selected bool
	}
	type tagOpt struct {
		ID      uint
		Name    string
		Checked bool
	}
	var catSel uint
	if post.CategoryID != nil {
		catSel = *post.CategoryID
	}
	var serSel uint
	if post.SeriesID != nil {
		serSel = *post.SeriesID
	}
	var catOptions []catOpt
	for _, c := range categories {
		lbl := c.Title
		if lbl == "" {
			lbl = c.Name
		}
		catOptions = append(catOptions, catOpt{ID: c.ID, Label: lbl, Selected: c.ID == catSel})
	}
	var seriesOptions []seriesOpt
	for _, s := range series {
		seriesOptions = append(seriesOptions, seriesOpt{ID: s.ID, Name: s.Name, Selected: s.ID == serSel})
	}
	selectedTags := map[uint]bool{}
	for _, t := range post.Tags {
		selectedTags[t.ID] = true
	}
	var tagOptions []tagOpt
	for _, t := range tags {
		tagOptions = append(tagOptions, tagOpt{ID: t.ID, Name: t.Name, Checked: selectedTags[t.ID]})
	}
	c.HTML(http.StatusOK, "admin/post_edit.html", gin.H{
		"active":        "posts",
		"post":          post,
		"catOptions":    catOptions,
		"seriesOptions": seriesOptions,
		"tagOptions":    tagOptions,
		"menus":         getMenuTree(),
		"path":          c.Request.URL.Path,
	})
}

type MenuNode struct {
	ID       uint
	Title    string
	Path     string
	Icon     string
	Children []MenuNode
}

func getMenuTree() []MenuNode {
	var items []db.Menu
	db.SQL.Order("parent_id asc, `order` asc, id asc").Find(&items)
	children := map[uint][]MenuNode{}
	var roots []MenuNode
	for _, m := range items {
		node := MenuNode{ID: m.ID, Title: m.Title, Path: m.Path, Icon: m.Icon}
		if m.ParentID != nil {
			children[*m.ParentID] = append(children[*m.ParentID], node)
		} else {
			roots = append(roots, node)
		}
	}
	for i := range roots {
		roots[i].Children = children[roots[i].ID]
	}
	return roots
}

func (a *Admin) MenusPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/menus.html", gin.H{"active": "menus", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

 func (a *Admin) SettingsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/settings.html", gin.H{"active": "settings", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

func (a *Admin) LinksPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/links.html", gin.H{"active": "links", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

type menuReq struct {
	Title    string `form:"title" json:"title"`
	Path     string `form:"path" json:"path"`
	Icon     string `form:"icon" json:"icon"`
	Order    int    `form:"order" json:"order"`
	ParentID *uint  `form:"parent_id" json:"parent_id"`
}

type linkReq struct {
	Name   string `form:"name" json:"name"`
	URL    string `form:"url" json:"url"`
	Active bool   `form:"active" json:"active"`
	Order  int    `form:"order" json:"order"`
}

type siteConfigReq struct {
	SiteTitle     string `form:"site_title" json:"site_title"`
	SiteICP       string `form:"site_icp" json:"site_icp"`
	SiteCopyright string `form:"site_copyright" json:"site_copyright"`
}

// @Summary 菜单列表
// @Tags admin
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/menus [get]
func (a *Admin) ListMenus(c *gin.Context) {
	var items []db.Menu
	db.SQL.Order("parent_id asc, `order` asc, id asc").Find(&items)
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// @Summary 创建菜单
// @Tags admin
// @Accept multipart/form-data
// @Produce json
// @Param title formData string true "菜单名"
// @Param path formData string false "链接地址"
// @Param icon formData string false "图标"
// @Param order formData int false "排序"
// @Param parent_id formData int false "父级ID"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /api/admin/menus [post]
func (a *Admin) CreateMenu(c *gin.Context) {
	// @Summary 创建菜单
	// @Tags admin
	// @Accept multipart/form-data
	// @Produce json
	// @Param title formData string true "菜单名"
	// @Param path formData string false "链接地址"
	// @Param icon formData string false "图标"
	// @Param order formData int false "排序"
	// @Param parent_id formData int false "父级ID"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Failure 400 {object} map[string]interface{}
	var req menuReq
	_ = c.ShouldBind(&req)
	if strings.TrimSpace(req.Title) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "菜单名必填"})
		return
	}
	item := db.Menu{Title: req.Title, Path: req.Path, Icon: req.Icon, Order: req.Order, ParentID: req.ParentID, Active: true}
	if err := db.SQL.Create(&item).Error; err != nil {
		logger.Error("create_menu_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": item.ID})
}

// @Summary 更新菜单
// @Tags admin
// @Accept multipart/form-data
// @Produce json
// @Param id path int true "菜单ID"
// @Param title formData string false "菜单名"
// @Param path formData string false "链接地址"
// @Param icon formData string false "图标"
// @Param order formData int false "排序"
// @Param parent_id formData int false "父级ID"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/menus/{id} [put]
func (a *Admin) UpdateMenu(c *gin.Context) {
	// @Summary 更新菜单
	// @Tags admin
	// @Accept multipart/form-data
	// @Produce json
	// @Param id path int true "菜单ID"
	// @Param title formData string false "菜单名"
	// @Param path formData string false "链接地址"
	// @Param icon formData string false "图标"
	// @Param order formData int false "排序"
	// @Param parent_id formData int false "父级ID"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	var req menuReq
	_ = c.ShouldBind(&req)
	var item db.Menu
	if err := db.SQL.First(&item, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到菜单"})
		return
	}
	item.Title = req.Title
	item.Path = req.Path
	item.Icon = req.Icon
	item.Order = req.Order
	item.ParentID = req.ParentID
	if err := db.SQL.Save(&item).Error; err != nil {
		logger.Error("update_menu_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// @Summary 删除菜单
// @Tags admin
// @Produce json
// @Param id path int true "菜单ID"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/menus/{id} [delete]
func (a *Admin) DeleteMenu(c *gin.Context) {
	// @Summary 删除菜单
	// @Tags admin
	// @Produce json
	// @Param id path int true "菜单ID"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if err := db.SQL.Delete(&db.Menu{}, id).Error; err != nil {
		logger.Error("delete_menu_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *Admin) ListLinks(c *gin.Context) {
	page := 1
	size := 50
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 200 {
			size = s
		}
	}
	var total int64
	db.SQL.Model(&db.FriendLink{}).Count(&total)
	var items []db.FriendLink
	db.SQL.Order("`order` asc, id asc").Limit(size).Offset((page - 1) * size).Find(&items)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "page": page, "pages": pages, "size": size, "total": total})
}

func (a *Admin) CreateLink(c *gin.Context) {
	var req linkReq
	_ = c.ShouldBind(&req)
	name := strings.TrimSpace(req.Name)
	url := strings.TrimSpace(req.URL)
	if name == "" || url == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "名称和地址必填"})
		return
	}
	item := db.FriendLink{Name: name, URL: url, Active: req.Active, Order: req.Order}
	if err := db.SQL.Create(&item).Error; err != nil {
		logger.Error("create_link_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": item.ID})
}

func (a *Admin) UpdateLink(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	var req linkReq
	_ = c.ShouldBind(&req)
	var item db.FriendLink
	if err := db.SQL.First(&item, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到链接"})
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		item.Name = strings.TrimSpace(req.Name)
	}
	if strings.TrimSpace(req.URL) != "" {
		item.URL = strings.TrimSpace(req.URL)
	}
	item.Active = req.Active
	item.Order = req.Order
	if err := db.SQL.Save(&item).Error; err != nil {
		logger.Error("update_link_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *Admin) DeleteLink(c *gin.Context) {
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if err := db.SQL.Delete(&db.FriendLink{}, id).Error; err != nil {
		logger.Error("delete_link_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *Admin) GetSiteConfig(c *gin.Context) {
	var items []db.SiteConfig
	keys := []string{"site_title", "site_icp", "site_copyright"}
	db.SQL.Where("`key` IN ?", keys).Find(&items)
	out := map[string]string{}
	for _, it := range items {
		out[it.Key] = it.Value
	}
	c.JSON(http.StatusOK, gin.H{
		"site_title":     out["site_title"],
		"site_icp":       out["site_icp"],
		"site_copyright": out["site_copyright"],
	})
}

func (a *Admin) SaveSiteConfig(c *gin.Context) {
	var req siteConfigReq
	_ = c.ShouldBind(&req)
	values := map[string]string{
		"site_title":     strings.TrimSpace(req.SiteTitle),
		"site_icp":       strings.TrimSpace(req.SiteICP),
		"site_copyright": strings.TrimSpace(req.SiteCopyright),
	}
	for k, v := range values {
		var item db.SiteConfig
		err := db.SQL.Where("`key` = ?", k).Assign(db.SiteConfig{Key: k, Value: v}).FirstOrCreate(&item).Error
		if err != nil {
			logger.Error("save_site_config_db_error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *Admin) RedisPage(c *gin.Context) {
	cfg, _ := config.Load()
	addr := cfg.Redis.Addr
	dbidx := cfg.Redis.DB
	c.HTML(http.StatusOK, "admin/redis.html", gin.H{"active": "redis", "menus": getMenuTree(), "addr": addr, "db": dbidx, "path": c.Request.URL.Path})
}

// @Summary Redis 基本信息与键列表
// @Tags admin
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/redis/info [get]
func (a *Admin) RedisInfo(c *gin.Context) {
	if db.Redis == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Redis 未启用"})
		return
	}
	infoAll, _ := db.Redis.Info(c, "all").Result()
	keys, err := db.Redis.Keys(c, "*").Result()
	if err != nil {
		logger.Error("redis_keys_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取键失败"})
		return
	}
	type kv struct {
		Key   string      `json:"key"`
		Type  string      `json:"type"`
		TTL   int64       `json:"ttl"`
		Value interface{} `json:"value"`
	}
	var out []kv
	for _, k := range keys {
		tp, _ := db.Redis.Type(c, k).Result()
		ttl, _ := db.Redis.TTL(c, k).Result()
		var val interface{}
		switch tp {
		case "string":
			val, _ = db.Redis.Get(c, k).Result()
		case "hash":
			val, _ = db.Redis.HGetAll(c, k).Result()
		case "list":
			val, _ = db.Redis.LRange(c, k, 0, -1).Result()
		case "set":
			val, _ = db.Redis.SMembers(c, k).Result()
		case "zset":
			val, _ = db.Redis.ZRangeWithScores(c, k, 0, -1).Result()
		default:
			val = nil
		}
		ttlSec := int64(ttl.Seconds())
		out = append(out, kv{Key: k, Type: tp, TTL: ttlSec, Value: val})
	}
	type cmdStat struct {
		Cmd           string  `json:"cmd"`
		Calls         int64   `json:"calls"`
		UsecPerCall   float64 `json:"usec_per_call"`
		TotalUsec     int64   `json:"usec"`
		RejectedCalls int64   `json:"rejected_calls"`
	}
	var stats []cmdStat
	infoMap := map[string]string{}
	for _, line := range strings.Split(infoAll, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "cmdstat_") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.TrimPrefix(parts[0], "cmdstat_")
			meta := parts[1]
			var cs cmdStat
			cs.Cmd = name
			for _, kvp := range strings.Split(meta, ",") {
				kvp = strings.TrimSpace(kvp)
				p := strings.SplitN(kvp, "=", 2)
				if len(p) != 2 {
					continue
				}
				switch p[0] {
				case "calls":
					if v, err := strconv.ParseInt(p[1], 10, 64); err == nil {
						cs.Calls = v
					}
				case "usec":
					if v, err := strconv.ParseInt(p[1], 10, 64); err == nil {
						cs.TotalUsec = v
					}
				case "usec_per_call":
					if v, err := strconv.ParseFloat(p[1], 64); err == nil {
						cs.UsecPerCall = v
					}
				case "rejected_calls":
					if v, err := strconv.ParseInt(p[1], 10, 64); err == nil {
						cs.RejectedCalls = v
					}
				}
			}
			stats = append(stats, cs)
			continue
		}
		if strings.Contains(line, ":") {
			p := strings.SplitN(line, ":", 2)
			infoMap[p[0]] = p[1]
		}
	}
	var clients, ops, totalCmds, uptime int64
	if v, err := strconv.ParseInt(infoMap["connected_clients"], 10, 64); err == nil {
		clients = v
	}
	if v, err := strconv.ParseInt(infoMap["instantaneous_ops_per_sec"], 10, 64); err == nil {
		ops = v
	}
	if v, err := strconv.ParseInt(infoMap["total_commands_processed"], 10, 64); err == nil {
		totalCmds = v
	}
	if v, err := strconv.ParseInt(infoMap["uptime_in_seconds"], 10, 64); err == nil {
		uptime = v
	}
	c.JSON(http.StatusOK, gin.H{
		"count":        len(keys),
		"items":        out,
		"memory":       infoMap["used_memory_human"],
		"clients":      clients,
		"ops_per_sec":  ops,
		"total_cmds":   totalCmds,
		"version":      infoMap["redis_version"],
		"uptime_sec":   uptime,
		"commandstats": stats,
		"role":         infoMap["role"],
		"total_conns":  infoMap["total_connections_received"],
		"used_memory":  infoMap["used_memory"],
	})
}

type loginReq struct {
	Username string `form:"username" json:"username"`
	Password string `form:"password" json:"password"`
}

// @Summary 管理员登录
// @Description 返回 JWT token
// @Tags admin
// @Accept multipart/form-data
// @Produce json
// @Param username formData string true "用户名"
// @Param password formData string true "密码"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /api/admin/login [post]
func (a *Admin) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBind(&req); err != nil {
		logger.Error("login_bad_request", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	var u db.AdminUser
	if err := db.SQL.Where("username = ?", req.Username).First(&u).Error; err != nil {
		audit.Write(c, "login_failure", "auth", nil, map[string]interface{}{"username": req.Username})
		logger.Error("login_user_not_found", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		audit.Write(c, "login_failure", "auth", nil, map[string]interface{}{"username": req.Username})
		logger.Error("login_password_mismatch", nil)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	claims := jwt.MapClaims{
		"sub": u.Username,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(a.secret))
	audit.Write(c, "login_success", "auth", nil, map[string]interface{}{"username": u.Username})
	c.SetCookie("admin_token", s, 86400, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"token": s})
}

func (a *Admin) Logout(c *gin.Context) {
	c.SetCookie("admin_token", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// @Summary 当前管理员信息
// @Tags admin
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/me [get]
func (a *Admin) Me(c *gin.Context) {
	// @Summary 当前管理员信息
	// @Tags admin
	// @Produce json
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type categoryReq struct {
	Title string `json:"title" form:"title"`
	Slug  string `json:"slug" form:"slug"`
}

// @Summary 分类列表
// @Tags admin
// @Produce json
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/categories [get]
func (a *Admin) ListCategories(c *gin.Context) {
	// @Summary 分类列表
	// @Tags admin
	// @Produce json
	// @Param page query int false "页码"
	// @Param size query int false "每页数量"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/categories [get]
	page := 1
	size := 20
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 200 {
			size = s
		}
	}
	var total int64
	db.SQL.Model(&db.Category{}).Count(&total)
	var items []db.Category
	db.SQL.Order("title asc").Limit(size).Offset((page - 1) * size).Find(&items)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "page": page, "pages": pages, "size": size, "total": total})
}

// @Summary 创建分类
// @Tags admin
// @Accept multipart/form-data
// @Produce json
// @Param title formData string true "分类标题"
// @Param slug formData string true "分类Slug"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /api/admin/categories [post]
func (a *Admin) CreateCategory(c *gin.Context) {
	// @Summary 创建分类
	// @Tags admin
	// @Accept multipart/form-data
	// @Produce json
	// @Param title formData string true "分类标题"
	// @Param slug formData string true "分类Slug"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Failure 400 {object} map[string]interface{}
	// @Router /api/admin/categories [post]
	var req categoryReq
	_ = c.ShouldBind(&req)
	req.Title = strings.TrimSpace(req.Title)
	req.Slug = strings.TrimSpace(req.Slug)
	if req.Title == "" || req.Slug == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	item := db.Category{Title: req.Title, Slug: req.Slug}
	if err := db.SQL.Create(&item).Error; err != nil {
		logger.Error("create_category_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	audit.Write(c, "create", "category", &item.ID, map[string]interface{}{"title": item.Title, "slug": item.Slug})
	c.JSON(http.StatusOK, gin.H{"id": item.ID})
}

// @Summary 删除分类
// @Tags admin
// @Produce json
// @Param id path int true "分类ID"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/categories/{id} [delete]
func (a *Admin) DeleteCategory(c *gin.Context) {
	// @Summary 删除分类
	// @Tags admin
	// @Produce json
	// @Param id path int true "分类ID"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/categories/{id} [delete]
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if err := db.SQL.Delete(&db.Category{}, id).Error; err != nil {
		logger.Error("delete_category_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	u := uint(id)
	audit.Write(c, "delete", "category", &u, nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type seriesReq struct {
	Name        string `json:"name" form:"name"`
	Description string `json:"description" form:"description"`
}

// @Summary 系列列表
// @Tags admin
// @Produce json
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/series [get]
func (a *Admin) ListSeries(c *gin.Context) {
	// @Summary 系列列表
	// @Tags admin
	// @Produce json
	// @Param page query int false "页码"
	// @Param size query int false "每页数量"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/series [get]
	page := 1
	size := 20
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 200 {
			size = s
		}
	}
	var total int64
	db.SQL.Model(&db.Series{}).Count(&total)
	var items []db.Series
	db.SQL.Order("name asc").Limit(size).Offset((page - 1) * size).Find(&items)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "page": page, "pages": pages, "size": size, "total": total})
}

// @Summary 创建系列
// @Tags admin
// @Accept multipart/form-data
// @Produce json
// @Param name formData string true "系列名称"
// @Param description formData string false "系列描述"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /api/admin/series [post]
func (a *Admin) CreateSeries(c *gin.Context) {
	// @Summary 创建系列
	// @Tags admin
	// @Accept multipart/form-data
	// @Produce json
	// @Param name formData string true "系列名称"
	// @Param description formData string false "系列描述"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Failure 400 {object} map[string]interface{}
	// @Router /api/admin/series [post]
	var req seriesReq
	_ = c.ShouldBind(&req)
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	item := db.Series{Name: strings.TrimSpace(req.Name), Description: strings.TrimSpace(req.Description)}
	if err := db.SQL.Create(&item).Error; err != nil {
		logger.Error("create_series_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	audit.Write(c, "create", "series", &item.ID, map[string]interface{}{"name": item.Name})
	c.JSON(http.StatusOK, gin.H{"id": item.ID})
}

// @Summary 删除系列
// @Tags admin
// @Produce json
// @Param id path int true "系列ID"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/series/{id} [delete]
func (a *Admin) DeleteSeries(c *gin.Context) {
	// @Summary 删除系列
	// @Tags admin
	// @Produce json
	// @Param id path int true "系列ID"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/series/{id} [delete]
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if err := db.SQL.Delete(&db.Series{}, id).Error; err != nil {
		logger.Error("delete_series_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	u := uint(id)
	audit.Write(c, "delete", "series", &u, nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// @Summary 标签列表
// @Tags admin
// @Produce json
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/tags [get]
func (a *Admin) ListTags(c *gin.Context) {
	// @Summary 标签列表
	// @Tags admin
	// @Produce json
	// @Param page query int false "页码"
	// @Param size query int false "每页数量"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/tags [get]
	page := 1
	size := 20
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 200 {
			size = s
		}
	}
	var total int64
	db.SQL.Model(&db.Tag{}).Count(&total)
	var items []db.Tag
	db.SQL.Order("name asc").Limit(size).Offset((page - 1) * size).Find(&items)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "page": page, "pages": pages, "size": size, "total": total})
}

// @Summary 访问日志列表
// @Tags admin
// @Produce json
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/views [get]
func (a *Admin) ListViews(c *gin.Context) {
	// @Summary 访问日志列表
	// @Tags admin
	// @Produce json
	// @Param page query int false "页码"
	// @Param size query int false "每页数量"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/views [get]
	page := 1
	size := 20
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 200 {
			size = s
		}
	}
	var total int64
	db.SQL.Model(&db.ViewLog{}).Count(&total)
	var items []db.ViewLog
	db.SQL.Order("created_at desc").Limit(size).Offset((page - 1) * size).Find(&items)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "page": page, "pages": pages, "size": size, "total": total})
}

// @Summary 后台文章列表
// @Tags admin
// @Produce json
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/posts [get]
func (a *Admin) ListPosts(c *gin.Context) {
	page := 1
	size := 20
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 200 {
			size = s
		}
	}
	var total int64
	db.SQL.Model(&db.Post{}).Count(&total)
	var posts []db.Post
	db.SQL.Preload("Tags").Order("created_at desc").Limit(size).Offset((page - 1) * size).Find(&posts)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	c.JSON(http.StatusOK, gin.H{"items": posts, "page": page, "pages": pages, "size": size, "total": total})
}

type postReq struct {
	Title        string `json:"title" form:"title"`
	Slug         string `json:"slug" form:"slug"`
	Summary      string `json:"summary" form:"summary"`
	Content      string `json:"content" form:"content"`
	CoverURL     string `json:"cover_url" form:"cover_url"`
	Status       string `json:"status" form:"status"`
	SeriesID     *uint  `json:"series_id" form:"series_id"`
	TagIDs       []uint `json:"tag_ids[]" form:"tag_ids[]"`
	PublishedStr string `json:"published" form:"published"`
}

// @Summary 创建文章
// @Tags admin
// @Accept multipart/form-data
// @Produce json
// @Param title formData string true "标题"
// @Param slug formData string true "Slug"
// @Param summary formData string false "摘要"
// @Param content formData string false "内容"
// @Param cover_url formData string false "封面URL"
// @Param status formData string false "状态"
// @Param category_id formData int true "分类ID"
// @Param series_id formData int false "系列ID"
// @Param tag_ids[] formData []int false "标签ID数组"
// @Param published formData string false "发布标记"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /api/admin/posts [post]
func (a *Admin) CreatePost(c *gin.Context) {
	// @Summary 创建文章
	// @Tags admin
	// @Accept multipart/form-data
	// @Produce json
	// @Param title formData string true "标题"
	// @Param slug formData string true "Slug"
	// @Param summary formData string false "摘要"
	// @Param content formData string false "内容"
	// @Param cover_url formData string false "封面URL"
	// @Param status formData string false "状态"
	// @Param category_id formData int true "分类ID"
	// @Param series_id formData int false "系列ID"
	// @Param tag_ids[] formData []int false "标签ID数组"
	// @Param published formData string false "发布标记"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Failure 400 {object} map[string]interface{}
	// @Router /api/admin/posts [post]
	var req postReq
	_ = c.ShouldBind(&req)
	if req.Title == "" {
		req.Title = c.PostForm("title")
	}
	if req.Slug == "" {
		req.Slug = c.PostForm("slug")
	}
	if strings.TrimSpace(req.Title) == "" || strings.TrimSpace(req.Slug) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "标题与 Slug 必填"})
		return
	}
	var cnt int64
	db.SQL.Model(&db.Post{}).Where("slug = ?", req.Slug).Count(&cnt)
	if cnt > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Slug 已存在"})
		return
	}
	if req.Summary == "" {
		req.Summary = c.PostForm("summary")
	}
	if req.Content == "" {
		req.Content = c.PostForm("content")
	}
	if req.CoverURL == "" {
		req.CoverURL = c.PostForm("cover_url")
	}
	if req.Status == "" {
		req.Status = c.PostForm("status")
	}
	if req.SeriesID == nil {
		if sid := c.PostForm("series_id"); sid != "" {
			if v, err := strconv.Atoi(sid); err == nil {
				u := uint(v)
				req.SeriesID = &u
			}
		}
	}
	if len(req.TagIDs) == 0 {
		arr := c.PostFormArray("tag_ids[]")
		if len(arr) == 0 {
			arr = c.PostFormArray("tag_ids")
		}
		for _, s := range arr {
			if v, err := strconv.Atoi(s); err == nil {
				req.TagIDs = append(req.TagIDs, uint(v))
			}
		}
	}
	if req.PublishedStr == "" {
		req.PublishedStr = c.PostForm("published")
	}
	p := db.Post{
		Title:    req.Title,
		Slug:     req.Slug,
		Summary:  req.Summary,
		Content:  req.Content,
		CoverURL: req.CoverURL,
		Status:   req.Status,
		SeriesID: req.SeriesID,
	}
	if cid := c.PostForm("category_id"); cid != "" {
		if v, err := strconv.Atoi(cid); err == nil {
			u := uint(v)
			p.CategoryID = &u
		}
	}
	if p.CategoryID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "必须选择分类"})
		return
	}
	if req.PublishedStr == "true" || req.PublishedStr == "on" || req.PublishedStr == "1" {
		t := time.Now()
		p.PublishedAt = &t
		p.Status = "published"
	}
	if err := db.SQL.Create(&p).Error; err != nil {
		logger.Error("create_post_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	if len(req.TagIDs) > 0 {
		var tags []db.Tag
		db.SQL.Where("id IN ?", req.TagIDs).Find(&tags)
		if err := db.SQL.Model(&p).Association("Tags").Replace(tags); err != nil {
			logger.Error("replace_post_tags_error", err)
		}
	}
	audit.Write(c, "create", "post", &p.ID, map[string]interface{}{"title": p.Title, "slug": p.Slug})
	c.JSON(http.StatusOK, gin.H{"id": p.ID})
}

// @Summary 更新文章
// @Tags admin
// @Accept multipart/form-data
// @Produce json
// @Param id path int true "文章ID"
// @Param title formData string true "标题"
// @Param slug formData string true "Slug"
// @Param summary formData string false "摘要"
// @Param content formData string false "内容"
// @Param cover_url formData string false "封面URL"
// @Param status formData string false "状态"
// @Param category_id formData int true "分类ID"
// @Param series_id formData int false "系列ID"
// @Param tag_ids[] formData []int false "标签ID数组"
// @Param published formData string false "发布标记"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/admin/posts/{id} [put]
func (a *Admin) UpdatePost(c *gin.Context) {
	// @Summary 更新文章
	// @Tags admin
	// @Accept multipart/form-data
	// @Produce json
	// @Param id path int true "文章ID"
	// @Param title formData string true "标题"
	// @Param slug formData string true "Slug"
	// @Param summary formData string false "摘要"
	// @Param content formData string false "内容"
	// @Param cover_url formData string false "封面URL"
	// @Param status formData string false "状态"
	// @Param category_id formData int true "分类ID"
	// @Param series_id formData int false "系列ID"
	// @Param tag_ids[] formData []int false "标签ID数组"
	// @Param published formData string false "发布标记"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Failure 404 {object} map[string]interface{}
	// @Router /api/admin/posts/{id} [put]
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	var req postReq
	_ = c.ShouldBind(&req)
	if req.Title == "" {
		req.Title = c.PostForm("title")
	}
	if req.Slug == "" {
		req.Slug = c.PostForm("slug")
	}
	if req.Summary == "" {
		req.Summary = c.PostForm("summary")
	}
	if req.Content == "" {
		req.Content = c.PostForm("content")
	}
	if req.CoverURL == "" {
		req.CoverURL = c.PostForm("cover_url")
	}
	if req.Status == "" {
		req.Status = c.PostForm("status")
	}
	if req.SeriesID == nil {
		if sid := c.PostForm("series_id"); sid != "" {
			if v, err := strconv.Atoi(sid); err == nil {
				u := uint(v)
				req.SeriesID = &u
			}
		}
	}
	if len(req.TagIDs) == 0 {
		arr := c.PostFormArray("tag_ids[]")
		if len(arr) == 0 {
			arr = c.PostFormArray("tag_ids")
		}
		for _, s := range arr {
			if v, err := strconv.Atoi(s); err == nil {
				req.TagIDs = append(req.TagIDs, uint(v))
			}
		}
	}
	if req.PublishedStr == "" {
		req.PublishedStr = c.PostForm("published")
	}
	var p db.Post
	if err := db.SQL.First(&p, id).Error; err != nil {
		logger.Error("update_post_not_found", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到文章"})
		return
	}
	p.Title = req.Title
	p.Slug = req.Slug
	p.Summary = req.Summary
	p.Content = req.Content
	p.CoverURL = req.CoverURL
	p.Status = req.Status
	p.SeriesID = req.SeriesID
	if cid := c.PostForm("category_id"); cid != "" {
		if v, err := strconv.Atoi(cid); err == nil {
			u := uint(v)
			p.CategoryID = &u
		}
	}
	if p.CategoryID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "必须选择分类"})
		return
	}
	if (req.PublishedStr == "true" || req.PublishedStr == "on" || req.PublishedStr == "1") && p.PublishedAt == nil {
		t := time.Now()
		p.PublishedAt = &t
		p.Status = "published"
	}
	if err := db.SQL.Save(&p).Error; err != nil {
		logger.Error("update_post_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	if len(req.TagIDs) > 0 {
		var tags []db.Tag
		db.SQL.Where("id IN ?", req.TagIDs).Find(&tags)
		if err := db.SQL.Model(&p).Association("Tags").Replace(tags); err != nil {
			logger.Error("replace_post_tags_error", err)
		}
	}
	audit.Write(c, "update", "post", &p.ID, map[string]interface{}{"title": p.Title, "slug": p.Slug})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// @Summary 删除文章
// @Tags admin
// @Produce json
// @Param id path int true "文章ID"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/posts/{id} [delete]
func (a *Admin) DeletePost(c *gin.Context) {
	// @Summary 删除文章
	// @Tags admin
	// @Produce json
	// @Param id path int true "文章ID"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/posts/{id} [delete]
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if err := db.SQL.Delete(&db.Post{}, id).Error; err != nil {
		logger.Error("delete_post_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	u := uint(id)
	audit.Write(c, "delete", "post", &u, nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type tagReq struct {
	Name string `json:"name" form:"name"`
}

// @Summary 创建标签
// @Tags admin
// @Accept multipart/form-data
// @Produce json
// @Param name formData string true "标签名"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /api/admin/tags [post]
func (a *Admin) CreateTag(c *gin.Context) {
	// @Summary 创建标签
	// @Tags admin
	// @Accept multipart/form-data
	// @Produce json
	// @Param name formData string true "标签名"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Failure 400 {object} map[string]interface{}
	// @Router /api/admin/tags [post]
	var req tagReq
	if err := c.ShouldBind(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}
	t := db.Tag{Name: strings.TrimSpace(req.Name)}
	if err := db.SQL.Create(&t).Error; err != nil {
		logger.Error("create_tag_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	audit.Write(c, "create", "tag", &t.ID, map[string]interface{}{"name": t.Name})
	c.JSON(http.StatusOK, gin.H{"id": t.ID})
}

// @Summary 删除标签
// @Tags admin
// @Produce json
// @Param id path int true "标签ID"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/tags/{id} [delete]
func (a *Admin) DeleteTag(c *gin.Context) {
	// @Summary 删除标签
	// @Tags admin
	// @Produce json
	// @Param id path int true "标签ID"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/tags/{id} [delete]
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if err := db.SQL.Delete(&db.Tag{}, id).Error; err != nil {
		logger.Error("delete_tag_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	u := uint(id)
	audit.Write(c, "delete", "tag", &u, nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// @Summary 评论列表
// @Tags admin
// @Produce json
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/comments [get]
func (a *Admin) ListComments(c *gin.Context) {
	// @Summary 评论列表
	// @Tags admin
	// @Produce json
	// @Param page query int false "页码"
	// @Param size query int false "每页数量"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/comments [get]
	page := 1
	size := 20
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 200 {
			size = s
		}
	}
	var total int64
	db.SQL.Model(&db.Comment{}).Count(&total)
	var items []db.Comment
	db.SQL.Order("created_at desc").Limit(size).Offset((page - 1) * size).Find(&items)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "page": page, "pages": pages, "size": size, "total": total})
}

// @Summary 审核评论
// @Tags admin
// @Produce json
// @Param id path int true "评论ID"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/comments/{id}/approve [put]
func (a *Admin) ApproveComment(c *gin.Context) {
	// @Summary 审核评论
	// @Tags admin
	// @Produce json
	// @Param id path int true "评论ID"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/comments/{id}/approve [put]
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if err := db.SQL.Model(&db.Comment{}).Where("id = ?", id).Update("approved", true).Error; err != nil {
		logger.Error("approve_comment_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	u := uint(id)
	audit.Write(c, "approve", "comment", &u, nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// @Summary 删除评论
// @Tags admin
// @Produce json
// @Param id path int true "评论ID"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/comments/{id} [delete]
func (a *Admin) DeleteComment(c *gin.Context) {
	// @Summary 删除评论
	// @Tags admin
	// @Produce json
	// @Param id path int true "评论ID"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/comments/{id} [delete]
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	if err := db.SQL.Delete(&db.Comment{}, id).Error; err != nil {
		logger.Error("delete_comment_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	u := uint(id)
	audit.Write(c, "delete", "comment", &u, nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// @Summary 上传附件
// @Tags admin
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "文件"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /api/admin/upload [post]
func (a *Admin) Upload(c *gin.Context) {
	// @Summary 上传附件
	// @Tags admin
	// @Accept multipart/form-data
	// @Produce json
	// @Param file formData file true "文件"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Failure 400 {object} map[string]interface{}
	// @Router /api/admin/upload [post]
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未选择文件"})
		return
	}
	ext := strings.ToLower(filepath.Ext(file.Filename))
	t := "other"
	if strings.HasPrefix(ext, ".jpg") || strings.HasPrefix(ext, ".jpeg") || strings.HasPrefix(ext, ".png") || strings.HasPrefix(ext, ".gif") || strings.HasPrefix(ext, ".webp") {
		t = "image"
	} else if strings.HasPrefix(ext, ".mp4") || strings.HasPrefix(ext, ".mov") || strings.HasPrefix(ext, ".avi") || strings.HasPrefix(ext, ".mkv") {
		t = "video"
	}
	dir := filepath.Join("web", "static", "uploads")
	_ = os.MkdirAll(dir, 0755)
	name := fmt.Sprintf("%d_%s", time.Now().UnixNano(), strings.ReplaceAll(file.Filename, " ", "_"))
	path := filepath.Join(dir, name)
	if err := c.SaveUploadedFile(file, path); err != nil {
		logger.Error("save_upload_file_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存文件失败"})
		return
	}
	url := "/static/uploads/" + name
	aRec := db.Attachment{
		FileName:  file.Filename,
		URL:       url,
		Path:      path,
		MimeType:  file.Header.Get("Content-Type"),
		SizeBytes: file.Size,
		Type:      t,
	}
	if err := db.SQL.Create(&aRec).Error; err != nil {
		logger.Error("create_attachment_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库错误"})
		return
	}
	audit.Write(c, "upload", "attachment", &aRec.ID, map[string]interface{}{"file": aRec.FileName, "url": aRec.URL, "type": aRec.Type})
	c.JSON(http.StatusOK, gin.H{"url": url})
}

func (a *Admin) AttachmentsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/attachments.html", gin.H{"active": "attachments", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

// @Summary 附件列表
// @Tags admin
// @Produce json
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/attachments [get]
func (a *Admin) ListAttachments(c *gin.Context) {
	// @Summary 附件列表
	// @Tags admin
	// @Produce json
	// @Param page query int false "页码"
	// @Param size query int false "每页数量"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/attachments [get]
	page := 1
	size := 20
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 200 {
			size = s
		}
	}
	var total int64
	db.SQL.Model(&db.Attachment{}).Count(&total)
	var items []db.Attachment
	db.SQL.Order("created_at desc").Limit(size).Offset((page - 1) * size).Find(&items)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "page": page, "pages": pages, "size": size, "total": total})
}

// @Summary 删除附件
// @Tags admin
// @Produce json
// @Param id path int true "附件ID"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/attachments/{id} [delete]
func (a *Admin) DeleteAttachment(c *gin.Context) {
	// @Summary 删除附件
	// @Tags admin
	// @Produce json
	// @Param id path int true "附件ID"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/attachments/{id} [delete]
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	var att db.Attachment
	if err := db.SQL.First(&att, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if att.Path != "" {
		_ = os.Remove(att.Path)
	}
	if err := db.SQL.Delete(&db.Attachment{}, id).Error; err != nil {
		logger.Error("delete_attachment_db_error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	u := uint(id)
	audit.Write(c, "delete", "attachment", &u, map[string]interface{}{"file": att.FileName})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *Admin) AuditPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/audit.html", gin.H{"active": "audit", "menus": getMenuTree(), "path": c.Request.URL.Path})
}

// @Summary 审计日志列表
// @Tags admin
// @Produce json
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Router /api/admin/audit [get]
func (a *Admin) ListAudit(c *gin.Context) {
	// @Summary 审计日志列表
	// @Tags admin
	// @Produce json
	// @Param page query int false "页码"
	// @Param size query int false "每页数量"
	// @Security Bearer
	// @Success 200 {object} map[string]interface{}
	// @Router /api/admin/audit [get]
	page := 1
	size := 20
	if v := c.Query("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := c.Query("size"); v != "" {
		if s, err := strconv.Atoi(v); err == nil && s > 0 && s <= 200 {
			size = s
		}
	}
	var total int64
	db.SQL.Model(&db.AuditLog{}).Count(&total)
	var items []db.AuditLog
	db.SQL.Order("created_at desc").Limit(size).Offset((page - 1) * size).Find(&items)
	pages := int((total + int64(size) - 1) / int64(size))
	if pages == 0 {
		pages = 1
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "page": page, "pages": pages, "size": size, "total": total})
}
