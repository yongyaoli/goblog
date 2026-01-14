package db

import (
	"context"
	"time"

	applogger "goblog/internal/logger"

	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

var SQL *gorm.DB
var Redis *redis.Client

func Init(mysqlDSN string, redisAddr string, redisPassword string, redisDB int, defaultAdminUser string, defaultAdminPass string) error {
	cfg := &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
		Logger: gormlogger.Default.LogMode(gormlogger.Info),
	}
	db, err := gorm.Open(mysql.Open(mysqlDSN), cfg)
	if err != nil {
		applogger.Error("mysql_init_error", err)
		return err
	}
	SQL = db
	if redisAddr != "" {
		Redis = redis.NewClient(&redis.Options{Addr: redisAddr, Password: redisPassword, DB: redisDB})
		if err := Redis.Ping(context.Background()).Err(); err != nil {
			applogger.Error("redis_ping_failed", err)
			Redis = nil
		}
	}
	err = SQL.AutoMigrate(
		&AdminUser{},
		&User{},
		&Category{},
		&Post{},
		&Tag{},
		&PostTag{},
		&Comment{},
		&Series{},
		&Attachment{},
		&ViewLog{},
		&AuditLog{},
		&Menu{},
		&FriendLink{},
		&SiteConfig{},
	)
	if err != nil {
		applogger.Error("mysql_auto_migrate_error", err)
		return err
	}
	if err := seedAdmin(defaultAdminUser, defaultAdminPass); err != nil {
		return err
	}
	if err := seedMenus(); err != nil {
		return err
	}
	return nil
}

type Model struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type User struct {
	Model
	Username     string `gorm:"uniqueIndex;size:64"`
	PasswordHash string `gorm:"size:255"`
	Role         string `gorm:"size:32"`
}

type AdminUser struct {
	Model
	Username     string `gorm:"uniqueIndex;size:64"`
	PasswordHash string `gorm:"size:255"`
	Status       string `gorm:"size:16"`
}

type Series struct {
	Model
	Name        string `gorm:"uniqueIndex;size:128"`
	Description string `gorm:"size:512"`
}

type Post struct {
	Model
	Title       string `gorm:"size:256"`
	Slug        string `gorm:"uniqueIndex;size:256"`
	Summary     string `gorm:"size:1024"`
	Content     string `gorm:"type:longtext"`
	CoverURL    string `gorm:"size:512"`
	Status      string `gorm:"size:16"`
	Views       int64  `gorm:"default:0"`
	SeriesID    *uint
	CategoryID  *uint
	PublishedAt *time.Time
	Tags        []Tag    `gorm:"many2many:post_tag;"`
	Category    Category `gorm:"foreignKey:CategoryID"`
}

type Tag struct {
	Model
	Name string `gorm:"uniqueIndex;size:64"`
}

type Category struct {
	Model
	Title string `gorm:"size:128"`
	Slug  string `gorm:"uniqueIndex;size:64"`
	// 保留旧字段以兼容历史数据（不再使用）
	Name string `gorm:"size:64"`
}

type PostTag struct {
	PostID uint `gorm:"primaryKey"`
	TagID  uint `gorm:"primaryKey"`
}

type Comment struct {
	Model
	PostID      uint
	AuthorName  string `gorm:"size:128"`
	AuthorEmail string `gorm:"size:256"`
	Content     string `gorm:"type:text"`
	Approved    bool   `gorm:"default:false"`
	ParentID    *uint
	IP          string `gorm:"size:64"`
}

type Attachment struct {
	Model
	FileName   string `gorm:"size:256"`
	URL        string `gorm:"size:512"`
	Path       string `gorm:"size:512"`
	MimeType   string `gorm:"size:128"`
	SizeBytes  int64
	Type       string `gorm:"size:32"`
	UploaderID *uint
	PostID     *uint
}

type ViewLog struct {
	Model
	PostID    uint
	IP        string `gorm:"size:64"`
	UserAgent string `gorm:"size:512"`
	Path      string `gorm:"size:512"`
}

type AuditLog struct {
	Model
	Admin      string `gorm:"size:64"`
	Action     string `gorm:"size:32"`
	Resource   string `gorm:"size:32"`
	ResourceID *uint
	Path       string `gorm:"size:512"`
	IP         string `gorm:"size:64"`
	UserAgent  string `gorm:"size:512"`
	Metadata   string `gorm:"type:text"`
}

type Menu struct {
	Model
	Title    string `gorm:"size:128"`
	Path     string `gorm:"size:256"`
	Icon     string `gorm:"size:64"`
	Order    int
	ParentID *uint
	Active   bool
}

type FriendLink struct {
	Model
	Name   string `gorm:"size:128"`
	URL    string `gorm:"size:512"`
	Active bool
	Order  int
}

type SiteConfig struct {
	Model
	Key   string `gorm:"uniqueIndex;size:64"`
	Value string `gorm:"size:1024"`
}
