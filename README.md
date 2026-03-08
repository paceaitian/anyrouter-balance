# AnyRouter Balance

AnyRouter 轻量余额查询服务。纯 HTTP + WAF 计算绕过，无需 Playwright/Chromium。

基于 [ishadows (linux.do)](https://linux.do/t/topic/1370431/151) 的 `acw_sc__v2` 纯计算绕过方案。

## 功能特性

- **实时余额查询** — 纯计算绕过 AnyRouter WAF（acw_sc__v2），无需浏览器
- **CC Switch 兼容** — 支持 NewAPI 模板（`/api/user/self`）和通用模板（`/user/balance`）
- **Web 管理界面** — 查看/刷新余额、添加/编辑/删除账号，暗色主题 Dashboard
- **极低资源占用** — 无 Playwright/Chromium，内存 ~35MB，适合小内存 VPS
- **缓存降级** — 实时查询失败时自动返回上次缓存的余额

## 快速部署

### Docker Compose（推荐）

```bash
# 1. 克隆项目
git clone https://github.com/paceaitian/anyrouter-balance.git
cd anyrouter-balance

# 2. 修改管理密码（必须）
#    编辑 docker-compose.yml，将 ADMIN_PASSWORD 改为你的密码
#    此密码同时用于 Web 管理界面登录和 CC Switch API Key

# 3. 启动服务
docker compose up -d
```

服务默认监听 `8080` 端口。访问 `http://<你的服务器IP>:8080` 进入管理界面。

### 自定义端口

修改 `docker-compose.yml` 中的端口映射：

```yaml
ports:
  - "9090:8080"    # 将宿主机 9090 映射到容器 8080
```

### 反向代理（HTTPS）

如果使用 Caddy / Nginx 反向代理，配置示例：

**Caddy：**
```
your-domain.com {
    reverse_proxy localhost:8080
}
```

**Nginx：**
```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 手动部署（不用 Docker）

```bash
# 安装依赖
pip install -r requirements.txt

# 设置环境变量并启动
export ADMIN_PASSWORD=your_password
export DB_PATH=./data/checkin.db
python -m uvicorn app:app --host 0.0.0.0 --port 8080
```

## 使用指南

### 1. 登录管理界面

访问服务地址，输入 `ADMIN_PASSWORD` 设置的密码登录。

### 2. 添加 AnyRouter 账号

每个账号需要 3 个信息：

| 字段 | 说明 | 获取方式 |
|------|------|----------|
| 账号名称 | 自定义标识（任意字符串） | 自己起一个方便记忆的名字，如 `myaccount` |
| API User ID | AnyRouter 用户数字 ID | 浏览器登录 AnyRouter → 访问 `/api/user/self` → 复制 `data.id` 的值 |
| Session Cookie | 认证凭据 | 浏览器 F12 → Application → Cookies → 复制 `session` 的值 |

**获取 API User ID 详细步骤：**

1. 浏览器登录 `https://anyrouter.top`
2. 地址栏输入 `https://anyrouter.top/api/user/self` 回车
3. 页面返回 JSON，找到 `"id": 123456`，这个数字就是 API User ID

**获取 Session Cookie 详细步骤：**

1. 浏览器登录 `https://anyrouter.top`
2. 按 F12 打开开发者工具
3. 切换到 Application（应用）标签页
4. 左侧 Cookies → `https://anyrouter.top`
5. 找到名为 `session` 的 Cookie，复制其 Value

> **注意：** Session Cookie 可能会过期。如果查询返回 401 错误，需要重新获取。

### 3. 查询余额

在管理界面点击"刷新全部余额"或单个账号的"刷新"按钮。

### 4. CC Switch 配置

在 CC Switch 中使用 **NewAPI** 模板：

| 配置项 | 值 |
|--------|------|
| **模板** | NewAPI |
| **Base URL** | `http://your-server:8080`（你的服务地址） |
| **API Key** | `密码:账号名称` |

**示例：** 假设管理密码为 `MyPass123`，账号名称为 `myaccount`：
- API Key 填写：`MyPass123:myaccount`

CC Switch 会调用 `/api/user/self` 端点实时查询余额并展示。

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ADMIN_PASSWORD` | `admin` | 管理密码（**请务必修改**），同时用于 CC Switch API Key 前缀 |
| `DB_PATH` | `/app/data/checkin.db` | SQLite 数据库路径（Docker 内） |
| `UPSTREAM` | `https://anyrouter.top` | AnyRouter 上游地址 |
| `PORT` | `8080` | 服务端口（仅 `python app.py` 直接运行时生效） |

## API 参考

### CC Switch 端点

| 端点 | 方法 | 认证方式 | 说明 |
|------|------|----------|------|
| `/api/user/self` | GET | Bearer `密码:账号名` | NewAPI 模板格式，返回 `{data: {quota, used_quota}}` |
| `/user/balance` | GET | Bearer `密码:账号名` | 通用模板格式，返回 `{total_balance, total_used}` |

**请求示例：**

```bash
# 查询单个账号余额（NewAPI 格式）
curl -H "Authorization: Bearer MyPass123:myaccount" http://localhost:8080/api/user/self

# 查询所有账号余额汇总（通用格式）
curl -H "Authorization: Bearer MyPass123" http://localhost:8080/user/balance
```

### 管理 API

所有管理 API 需要先登录获取 Cookie。

| 端点 | 方法 | 说明 |
|------|------|------|
| `/admin/login` | POST | 登录，Body: `{"password": "xxx"}` |
| `/admin/logout` | POST | 登出 |
| `/admin/api/accounts` | GET | 列出所有账号及缓存余额 |
| `/admin/api/accounts` | POST | 添加账号，Body: `{"name", "api_user", "session"}` |
| `/admin/api/accounts/{name}` | PUT | 更新账号，Body: `{"api_user", "session", "enabled"}` |
| `/admin/api/accounts/{name}` | DELETE | 删除账号 |
| `/admin/api/refresh/{name}` | POST | 实时刷新单个账号余额 |
| `/admin/api/refresh` | POST | 实时刷新所有启用账号余额 |

## 架构说明

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│  CC Switch   │────▶│ anyrouter-balance │────▶│  AnyRouter   │
│  / 浏览器    │◀────│   (FastAPI)       │◀────│    WAF       │
└─────────────┘     └──────────────────┘     └──────────────┘
                           │
                     ┌─────▼─────┐
                     │  SQLite   │
                     │ (缓存余额) │
                     └───────────┘
```

**WAF 绕过原理：**

AnyRouter 使用知道创宇加速乐 WAF，首次访问会返回 JS challenge 页面：

1. 从返回的 HTML 中提取 `var arg1 = '...'`（40 位 hex 字符串）
2. 通过 UNSBOX 置换表（40 位固定映射）重排字符顺序
3. 与固定 XOR_KEY `3000176000856006061501533003690027800375` 异或
4. 得到 `acw_sc__v2` Cookie 值

整个过程是纯数学计算（置换 + 异或），无需浏览器执行 JavaScript。

**查询流程：**

1. GET 请求触发 WAF → 获取 `acw_tc`、`cdn_sec_tc` Cookie + 计算 `acw_sc__v2`
2. 携带所有 Cookie + session Cookie → GET `/api/user/self` 获取余额
3. 若仍被 WAF 拦截，从响应中重新提取并重试一次
4. 成功后更新 SQLite 缓存；失败时返回上次缓存值

## 项目结构

```
anyrouter-balance/
├── app.py              # 主服务（FastAPI + 内嵌前端）
├── Dockerfile          # Docker 镜像定义
├── docker-compose.yml  # Docker Compose 编排
├── requirements.txt    # Python 依赖
├── .gitignore
├── .dockerignore
└── data/               # 运行时数据（git 忽略）
    └── checkin.db      # SQLite 数据库
```

## 常见问题

**Q: Session Cookie 多久过期？**
A: 取决于 AnyRouter 的 session 策略，通常较长。过期后查询会返回 401 错误，重新获取 Cookie 即可。

**Q: 查询会给服务器带来负担吗？**
A: 每次查询仅发 2 个 HTTP 请求（WAF + API），无浏览器开销。CC Switch 通常每分钟查询一次，对 AnyRouter 几乎没有压力。

**Q: 和 Playwright 方案有什么区别？**
A: Playwright 方案需要启动完整的 Chromium 浏览器执行 JS，内存 500MB+；本项目纯 HTTP 计算绕过，内存 ~35MB，且不需要安装 Chromium。

**Q: 支持多个 AnyRouter 账号吗？**
A: 支持。在管理界面添加多个账号，每个账号独立查询。CC Switch 通过 API Key 中的账号名指定查询哪个账号。

## 致谢

- [ishadows](https://linux.do/t/topic/1370431/151) — acw_sc__v2 纯计算绕过方案
- [zhx47](https://linux.do/t/topic/1370431) — 原始 AnyRouter 动态 cookie 验证思路

## License

MIT
