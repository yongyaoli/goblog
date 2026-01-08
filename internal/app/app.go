package app

import (
	"fmt"
	"os"
	"path/filepath"

	docs "goblog/docs"
	"goblog/internal/config"
	"goblog/internal/db"
	"goblog/internal/handlers"
	"goblog/internal/logger"
	"goblog/internal/middleware"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func Run(port int) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	_ = logger.Init(filepath.Join("logs", "app.log"))
	secret := cfg.JWT.Secret
	if secret == "" {
		secret = "change-this-secret"
	}
	err = db.Init(cfg.MySQL.DSN, cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB, cfg.Admin.DefaultUser, cfg.Admin.DefaultPass)
	if err != nil {
		logger.Error("db_init_error", err)
		return err
	}
	r := gin.Default()
	r.Use(middleware.CORS(), middleware.AccessLog())
	docs.SwaggerInfo.BasePath = "/"
	staticDir := filepath.Join("web", "static")
	templatesDir := filepath.Join("web", "templates")
	_ = os.MkdirAll(staticDir, 0755)
	_ = os.MkdirAll(templatesDir, 0755)
	r.Use(static.Serve("/static", static.LocalFile(staticDir, true)))
	r.LoadHTMLGlob(filepath.Join(templatesDir, "*", "*.html"))
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	pub := handlers.NewPublic()
	admin := handlers.NewAdmin(secret)
	r.GET("/", pub.Index)
	r.GET("/post/:slug", pub.Post)
	r.POST("/post/:id/comments", pub.CreateComment)
	r.GET("/archive", pub.Archive)
	r.GET("/series/:id", pub.Series)
	r.GET("/tags/:name", pub.TagPosts)
	r.GET("/categories/:name", pub.CategoryPosts)
	r.GET("/admin", admin.LoginPage)
	r.GET("/admin/dashboard", admin.DashboardPage)
	r.GET("/admin/posts/new", admin.PostEditPage)
	r.GET("/admin/posts/:id/edit", admin.PostEditPage)
	r.GET("/admin/categories", admin.CategoriesPage)
	r.GET("/admin/tags", admin.TagsPage)
	r.GET("/admin/series", admin.SeriesPage)
	r.GET("/admin/comments", admin.CommentsPage)
	r.GET("/admin/views", admin.ViewsPage)
	r.GET("/admin/audit", admin.AuditPage)
	r.GET("/admin/attachments", admin.AttachmentsPage)
	r.GET("/admin/attachment", admin.AttachmentsPage)
	r.GET("/admin/menus", admin.MenusPage)
	r.GET("/admin/redis", admin.RedisPage)
	r.GET("/admin/links", admin.LinksPage)
	r.GET("/admin/settings", admin.SettingsPage)
	r.GET("/rss.xml", pub.RSS)
	r.GET("/sitemap.xml", pub.Sitemap)
	api := r.Group("/api")
	api.POST("/admin/login", admin.Login)
	api.Use(middleware.AuthRequired(secret))
	api.GET("/admin/me", admin.Me)
	api.GET("/admin/posts", admin.ListPosts)
	api.POST("/admin/posts", admin.CreatePost)
	api.PUT("/admin/posts/:id", admin.UpdatePost)
	api.DELETE("/admin/posts/:id", admin.DeletePost)
	api.GET("/admin/tags", admin.ListTags)
	api.POST("/admin/tags", admin.CreateTag)
	api.DELETE("/admin/tags/:id", admin.DeleteTag)
	api.GET("/admin/categories", admin.ListCategories)
	api.POST("/admin/categories", admin.CreateCategory)
	api.DELETE("/admin/categories/:id", admin.DeleteCategory)
	api.GET("/admin/series", admin.ListSeries)
	api.POST("/admin/series", admin.CreateSeries)
	api.DELETE("/admin/series/:id", admin.DeleteSeries)
	api.GET("/admin/comments", admin.ListComments)
	api.PUT("/admin/comments/:id/approve", admin.ApproveComment)
	api.DELETE("/admin/comments/:id", admin.DeleteComment)
	api.GET("/admin/views", admin.ListViews)
	api.GET("/admin/audit", admin.ListAudit)
	api.POST("/admin/upload", admin.Upload)
	api.GET("/admin/attachments", admin.ListAttachments)
	api.DELETE("/admin/attachments/:id", admin.DeleteAttachment)
	api.GET("/admin/menus", admin.ListMenus)
	api.POST("/admin/menus", admin.CreateMenu)
	api.PUT("/admin/menus/:id", admin.UpdateMenu)
	api.DELETE("/admin/menus/:id", admin.DeleteMenu)
	api.GET("/admin/redis/info", admin.RedisInfo)
	api.GET("/admin/links", admin.ListLinks)
	api.POST("/admin/links", admin.CreateLink)
	api.PUT("/admin/links/:id", admin.UpdateLink)
	api.DELETE("/admin/links/:id", admin.DeleteLink)
	api.GET("/admin/site-config", admin.GetSiteConfig)
	api.POST("/admin/site-config", admin.SaveSiteConfig)
	if cfg.Server.Port != 0 {
		port = cfg.Server.Port
	}
	return r.Run(fmt.Sprintf(":%d", port))
}
