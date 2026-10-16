# GoBlog 博客系统

一个基于 Go 语言开发的轻量、高效的个人/企业级博客与管理后台系统。支持文章撰写、分类标签、系列专栏、评论审核、富文本编辑、附件管理、访问日志分析及 Redis 缓存/监控。

---

## 目录
- [主要特性](#主要特性)
- [中间件与技术栈清单](#中间件与技术栈清单)
  - [基础服务与数据中间件](#基础服务与数据中间件)
  - [应用层 HTTP 中间件](#应用层-http-中间件)
  - [核心依赖库及版本](#核心依赖库及版本)
- [项目目录结构](#项目目录结构)
- [Docker 运行与部署指南](#docker-运行与部署指南)
  - [前置准备](#前置准备)
  - [方式一：Docker Compose 一键全栈启动（推荐）](#方式一docker-compose-一键全栈启动推荐)
  - [方式二：Docker Compose 仅启动应用（连接已有数据库）](#方式二docker-compose-仅启动应用连接已有数据库)
  - [方式三：原生 Docker 镜像构建与运行](#方式三原生-docker-镜像构建与运行)
  - [Docker 环境变量配置说明](#docker-环境变量配置说明)
  - [常用 Docker 运维命令](#常用-docker-运维命令)
- [本地开发运行指南](#本地开发运行指南)
- [默认账号与初始数据](#默认账号与初始数据)
- [API 与 Swagger 文档](#api-与-swagger-文档)

---

## 主要特性

- **前台展示**：文章列表与分页、文章详情（浏览计数、代码高亮渲染）、分类检索、标签聚合、系列文章、归档时光轴、发布日历统计、友链展示、RSS 订阅 (`/rss.xml`) 与 Sitemap 站点地图 (`/sitemap.xml`)。
- **后台管理**：基于 Cookie/JWT 双重鉴权；文章增删改查（草稿/发布）、分类/标签/系列专栏管理、评论审核与防刷、附件上传与预览、系统访问统计、操作审计日志、动态后台菜单管理、Redis 实时状态监控、站点基础配置。
- **安全与稳定性**：密码通过 `bcrypt` 散列加盐存储、JWT 鉴权拦截、基于 Redis/MySQL 双重降级的评论发布频率限制、CORS 跨域防护与访问日志追踪。
- **轻量易部署**：Docker 多阶段构建生成仅几十兆的 Alpine 镜像，提供一键全栈 Docker Compose 编排脚本。

---

## 中间件与技术栈清单

本项目使用的中间件主要包括**外部基础设施/数据中间件**、**Web 应用程序内部中间件**以及**核心支撑框架**：

### 基础服务与数据中间件

| 中间件名称 | 镜像/推荐版本 | 必需/可选 | 作用说明 |
| :--- | :--- | :--- | :--- |
| **MySQL** | `mysql:5.7`（支持 5.7+ / 8.0+） | **必需** | 核心持久化存储，存储文章、分类、标签、用户、评论、附件、审计与访问日志等数据，采用 `utf8mb4` 字符集 |
| **Redis** | `redis:alpine`（推荐 6.x / 7.x） | **可选** | 评论发布防刷频率控制（10分钟同一 IP 频控）、数据缓存以及后台 Redis 运行状态与键值监控（未开启时限流降级为 MySQL 查询） |

### 应用层 HTTP 中间件

位于 [`internal/middleware/`](file:///d:/github/goblog/internal/middleware) 目录下：

1. **跨域处理中间件 (`CORS`)**：
   - 文件：[`cors.go`](file:///d:/github/goblog/internal/middleware/cors.go)
   - 作用：统一设置跨域响应头（`Access-Control-Allow-Origin: *`、支持 GET/POST/PUT/DELETE），并直接拦截处理 HTTP `OPTIONS` 预检请求（返回 204）。
2. **访问日志中间件 (`AccessLog`)**：
   - 文件：[`accesslog.go`](file:///d:/github/goblog/internal/middleware/accesslog.go)
   - 作用：自动拦截非 API、非静态资源请求，提取客户端 IP、UserAgent、Path 异步落库至 `view_log` 表，用于站点 PV/UV 流量分析。
3. **API JWT 鉴权中间件 (`AuthRequired`)**：
   - 文件：[`auth.go`](file:///d:/github/goblog/internal/middleware/auth.go)
   - 作用：基于 `golang-jwt/jwt/v5`，针对 `/api/admin/*` 管理后台数据接口校验请求头中的 `Authorization: Bearer <Token>`。
4. **后台页面访问鉴权中间件 (`AdminPageAuth`)**：
   - 文件：[`auth.go`](file:///d:/github/goblog/internal/middleware/auth.go)
   - 作用：针对 SSR 服务端渲染页面 `/admin/*`，校验 Cookie 中的 `admin_token`，未登录或 Token 失效则重定向回 `/admin` 登录页。
5. **框架内置中间件**：
   - `gin.Logger()` 与 `gin.Recovery()`（通过 `gin.Default()` 启用）：提供终端控制台日志与 Panic 异常恢复。
   - `static.Serve`（基于 `github.com/gin-contrib/static`）：提供 `/static` 路由下的静态文件高效托管。

### 核心依赖库及版本

| 依赖组件 | 引用路径 | 引入版本 | 用途 |
| :--- | :--- | :--- | :--- |
| **Go 运行时** | `Go Toolchain` | `>= 1.24.3` | 项目开发与构建所使用的 Go 版本 |
| **Gin** | `github.com/gin-gonic/gin` | `v1.11.0` | 高性能核心 Web 路由与 HTTP 处理框架 |
| **GORM** | `gorm.io/gorm` | `v1.31.1` | 对象关系映射（ORM）核心组件 |
| **GORM MySQL 驱动** | `gorm.io/driver/mysql` | `v1.6.0` | GORM 针对 MySQL 的官方数据库驱动适配 |
| **MySQL 底层驱动** | `github.com/go-sql-driver/mysql` | `v1.8.1` | Go 官方标准库兼容的底层 MySQL 驱动 |
| **go-redis** | `github.com/redis/go-redis/v9` | `v9.17.2` | 官方高并发 Redis 客户端库 |
| **JWT** | `github.com/golang-jwt/jwt/v5` | `v5.3.0` | 管理员 Token 签发与解析验证 |
| **Bcrypt 散列** | `golang.org/x/crypto` | `v0.46.0` | 密码 Hash 安全散列算法 |
| **YAML 解析** | `gopkg.in/yaml.v3` | `v3.0.1` | 配置文件 `config.yaml` 格式反序列化 |
| **Swagger 文档生成** | `github.com/swaggo/swag` | `v1.16.6` | 自动化生成 OpenAPI / Swagger 规范文档 |
| **Gin-Swagger 中间件** | `github.com/swaggo/gin-swagger` | `v1.6.1` | 在 Gin 路由中集成 Swagger UI 展示界面 |
| **静态资源处理** | `github.com/gin-contrib/static` | `v1.1.5` | 静态资源与上传目录目录服务 |

---

## 项目目录结构

```text
goblog/
├── config/                          # 配置文件目录
│   ├── config.example.yaml          # 示例配置文件
│   └── config.yaml                  # 实际运行配置文件（可由环境变量覆盖）
├── db/                              # 数据库初始化与辅助脚本
│   └── menu.sql                     # 默认菜单数据脚本
├── docs/                            # Swagger API 文档生成物
│   ├── docs.go
│   ├── swagger.json
│   └── swagger.yaml
├── internal/                        # 内部核心业务代码
│   ├── app/                         # 应用入口引导与路由注册 (app.go)
│   ├── audit/                       # 审计日志模块 (audit.go)
│   ├── config/                      # 配置结构与环境变量解析 (config.go)
│   ├── db/                          # GORM 实体定义、迁移与 Seed 初始化 (db.go, seed.go)
│   ├── handlers/                    # 控制器层 (public.go, admin.go)
│   ├── logger/                      # 日期轮转日志记录器 (logger.go)
│   └── middleware/                  # HTTP 中间件 (accesslog.go, auth.go, cors.go)
├── logs/                            # 应用日志存放目录
├── web/                             # 前端资源
│   ├── static/                      # CSS、JS、TinyMCE、以及上传文件 uploads/
│   └── templates/                   # Go HTML 模板文件 (admin/ 和 public/)
├── Dockerfile                       # 多阶段 Docker 构建文件
├── docker-compose.yml               # 全栈一键编排脚本（App + MySQL + Redis）
├── docker-compose.app-only.yml      # 独立 App 编排脚本（对接外部数据库）
├── go.mod                           # Go 模块依赖定义
├── go.sum                           # Go 模块依赖校验锁
└── main.go                          # 启动主入口
```

---

## Docker 运行与部署指南

项目提供了完整的 Dockerfile 与两套 Docker Compose 配置方案，适合不同的部署环境。

### 前置准备

确保您的机器已安装并启动 **Docker** 与 **Docker Compose**（Docker Desktop 或 Linux 下的 Docker Engine）。

```bash
# 检查 Docker 版本
docker --version
docker compose version
```

拷贝或确认配置文件存在：
```bash
cp config/config.example.yaml config/config.yaml
```

---

### 方式一：Docker Compose 一键全栈启动（推荐）

该方式会自动化启动 3 个容器：
- `goblog-mysql` (MySQL 5.7)
- `goblog-redis` (Redis Alpine)
- `goblog-app` (GoBlog 博客系统)

并且自动创建网络互通、挂载持久化数据卷（`mysql_data`、`redis_data`、日志文件和上传目录）。

#### 1. 启动所有服务
在项目根目录下执行：
```bash
docker compose up -d --build
```
> 参数说明：`-d` 表示后台运行，`--build` 表示构建镜像。

#### 2. 检查运行状态
```bash
docker compose ps
```
若正常运行，会看到 3 个服务均处于 `Up` / `running` 状态。

#### 3. 访问服务
- 前台主页：`http://localhost:8080/`
- 后台登录：`http://localhost:8080/admin`
- Swagger API 文档：`http://localhost:8080/swagger/index.html`

---

### 方式二：Docker Compose 仅启动应用（连接已有数据库）

若您已在本地、云服务器或 RDS 上部署了 MySQL 和 Redis，可直接使用独立编排文件：

#### 1. 修改连接配置
编辑 `docker-compose.app-only.yml` 中的环境变量：
```yaml
environment:
  - GOBLOG_PORT=8080
  - GOBLOG_MYSQL_DSN=用户名:密码@tcp(MySQL宿主机或内网IP:3306)/goblog?charset=utf8mb4&parseTime=True&loc=Local
  - GOBLOG_REDIS_ADDR=Redis宿主机或内网IP:6379
  - GOBLOG_REDIS_PASSWORD=你的Redis密码
  - GOBLOG_REDIS_DB=0
  - GOBLOG_JWT_SECRET=自定义一段强随机字符串
```

#### 2. 启动服务
```bash
docker compose -f docker-compose.app-only.yml up -d --build
```

---

### 方式三：原生 Docker 镜像构建与运行

#### 1. 构建 Docker 镜像
```bash
docker build -t goblog:latest .
```

#### 2. 运行容器
```bash
docker run -d \
  --name goblog \
  -p 8080:8080 \
  -e GOBLOG_PORT=8080 \
  -e GOBLOG_MYSQL_DSN="root:rootpassword@tcp(host.docker.internal:3306)/goblog?charset=utf8mb4&parseTime=True&loc=Local" \
  -e GOBLOG_JWT_SECRET="your-jwt-secret-key" \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/web/static/uploads:/app/web/static/uploads \
  goblog:latest
```

---

### Docker 环境变量配置说明

容器启动时支持通过环境变量动态覆盖 `config/config.yaml` 对应配置：

| 环境变量名 | 默认/示例值 | 对应说明 |
| :--- | :--- | :--- |
| `GOBLOG_PORT` | `8080` | HTTP 服务监听端口 |
| `GOBLOG_MYSQL_DSN` | `root:rootpassword@tcp(mysql:3306)/goblog?...` | MySQL 数据库连接串（需包含 `parseTime=True&loc=Local`） |
| `GOBLOG_REDIS_ADDR` | `redis:6379` | Redis 主机与端口（留空表示不启用 Redis） |
| `GOBLOG_REDIS_PASSWORD` | `""` | Redis 访问密码 |
| `GOBLOG_REDIS_DB` | `0` | Redis 数据库索引号 |
| `GOBLOG_JWT_SECRET` | `your-secret-key-change-it` | JWT Token 签名密钥（生产环境务必更改） |
| `GOBLOG_ADMIN_USER` | `admin` | 系统首次启动初始化的管理员账号 |
| `GOBLOG_ADMIN_PASS` | `admin123` | 系统首次启动初始化的管理员密码 |

---

### 常用 Docker 运维命令

```bash
# 查看容器实时运行日志
docker compose logs -f app

# 查看数据库容器日志
docker compose logs -f mysql

# 重启应用服务
docker compose restart app

# 停止并移除容器（数据保留在 volume 中）
docker compose down

# 停止并彻底清理数据卷（注意：会清空数据库数据）
docker compose down -v

# 进入应用容器终端
docker exec -it goblog-app sh
```

---

## 本地开发运行指南

#### 1. 准备本地 MySQL
在本地创建数据库并指定编码：
```sql
CREATE DATABASE goblog CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

#### 2. 配置与启动
```bash
# 复制配置文件并修改 MySQL / Redis 连接参数
cp config/config.example.yaml config/config.yaml

# 下载依赖并本地运行
go mod download
go run .
```

系统启动时会自动执行 GORM AutoMigrate 建表，无需手动执行 DDL 脚本。

---

## 默认账号与初始数据

- **后台入口**：`http://localhost:8080/admin`
- **默认管理员账号**：`admin`
- **默认管理员密码**：`admin123`
- **初始数据**：首次启动会自动检查 `admin_user` 表，若为空将自动创建默认管理员；同时会自动向 `menu` 表初始化 13 项系统管理菜单（文章、分类、标签、系列、评论、访问统计、审计日志、资源管理、菜单管理、Redis监控、友链、站点配置等）。

---

## API 与 Swagger 文档

项目集成了 Swagger API 在线交互文档：
- **Swagger 地址**：`http://localhost:8080/swagger/index.html`
- **重新生成文档**（修改 API 注释后）：
  ```bash
  go install github.com/swaggo/swag/cmd/swag@v1.16.6
  swag init
  ```
