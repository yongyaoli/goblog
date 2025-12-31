# GoBlog 博客系统

一个基于 Go 的简洁博客与后台管理系统，支持 MySQL 5.7、可选 Redis 缓存、富文本编辑、附件上传、评论审核、标签、归档与系列。

## 项目结构
- main.go：应用入口
- internal/
  - app/：应用启动与路由 [app.go](file:///d:/gitee/gocms/internal/app/app.go)
  - config/：配置加载（YAML） [config.go](file:///d:/gitee/gocms/internal/config/config.go)
  - db/：数据库模型与初始化 [db.go](file:///d:/gitee/gocms/internal/db/db.go)、[seed.go](file:///d:/gitee/gocms/internal/db/seed.go)
  - handlers/：HTTP 处理器（Public/Admin） [public.go](file:///d:/gitee/gocms/internal/handlers/public.go)、[admin.go](file:///d:/gitee/gocms/internal/handlers/admin.go)
  - middleware/：中间件（CORS/JWT/访问日志）
- web/
  - templates/：前台与后台 HTML 模板
  - static/：静态资源与上传目录
- config/
  - config.example.yaml：示例配置文件

## 主要框架与库
- Gin（github.com/gin-gonic/gin）：高性能 Web 框架，用于路由与中间件。
- GORM（gorm.io/gorm、gorm.io/driver/mysql）：ORM 库，负责模型定义与数据库操作。
- go-redis（github.com/redis/go-redis/v9）：Redis 客户端，用于缓存。
- JWT（github.com/golang-jwt/jwt/v5）：JSON Web Token，用于管理员接口鉴权。
- bcrypt（golang.org/x/crypto/bcrypt）：密码散列存储。
- TinyMCE（前端）：富文本编辑器，支持图片/视频插入。
- Bootstrap（前端）：美观的响应式 UI。

## 配置文件
复制示例并填写真实信息：
```
cp config/config.example.yaml config/config.yaml
```

配置说明（YAML）：
- server.port：服务端口
- mysql.dsn：MySQL 连接串（兼容 5.7）
- redis.addr / redis.password：Redis 地址与密码（可选）
- jwt.secret：JWT 密钥（用于生成管理员接口 token）
- admin.default_user / admin.default_pass：初始化默认管理员账号（仅首次运行）

支持通过环境变量 CONFIG_PATH 指定配置文件路径。

## 管理员账号存储
管理员账号使用专门的表 admin_user 存储，字段包含 Username/PasswordHash/Status。首次启动会按配置文件中 admin.* 初始化一个默认管理员（若表为空）。

## 运行与部署
- 本地启动：
  - 创建 MySQL 数据库：`CREATE DATABASE goblog CHARACTER SET utf8mb4;`
  - 准备 `config/config.yaml` 并执行：`go run .`
  - 访问前台：`http://localhost:8080/`；后台登录：`/admin`
- 服务器部署（宝塔）：
  - 构建二进制：`GOOS=linux GOARCH=amd64 go build -o goblog`
  - 上传二进制与 web/、config/ 目录到服务器
  - 使用 systemd 托管进程，Nginx 反向代理到 `http://127.0.0.1:<port>`

## 功能说明
- 前台：列表、详情（浏览量累加）、归档、系列、标签页、分类页、评论展示（审核后）
- 后台：登录、文章增删改查、分类管理、标签管理、系列管理、评论审核、附件上传、浏览记录
- 附件：保存到 `web/static/uploads` 并记录数据库条目
- 缓存：首页列表缓存（Redis，可选）
- 中间件：CORS、JWT 鉴权（API）、访问日志记录
- 审计：记录管理员登录、文章/分类/标签/系列/评论的增删改与操作

## 后续可扩展项
- 权限分级：超级管理员/编辑/审稿，操作审计日志
- 登录保护：验证码、失败次数限制、IP 限制、二次验证
- 内容工作流：草稿自动保存、版本历史、定时发布与审批
- 富文本增强：代码块复制按钮、数学公式（KaTeX）、图片裁剪压缩
- SEO 与分发：sitemap、RSS、OG/Meta、站内搜索、结构化数据
- 前端体验：主题与暗黑模式、文章 TOC、阅读进度、上一篇/下一篇
- 评论体系：反垃圾策略（关键词/频率/黑名单）、邮件通知、第三方登录
- 数据运营：PV/UV 统计、热门文章榜、读者地域分析
- 性能优化：页面/片段缓存、CDN 静态加速、图片自适应与懒加载
- 架构扩展：多站点/多语言、队列与定时任务、灰度发布
