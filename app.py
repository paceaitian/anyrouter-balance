# AnyRouter 轻量余额查询服务
# 纯 HTTP + WAF 计算绕过，无需 Playwright/Chromium
# 基于 ishadows (linux.do) 的 acw_sc__v2 纯计算方案

import asyncio
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from typing import Optional

import httpx
from fastapi import Cookie, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("anyrouter-balance")

app = FastAPI(title="AnyRouter Balance API")

DB_PATH = os.getenv("DB_PATH", "/app/data/checkin.db")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
UPSTREAM = os.getenv("UPSTREAM", "https://anyrouter.top")
RELAY_URL = os.getenv("RELAY_URL", "")
FEISHU_WEBHOOK = os.getenv("FEISHU_WEBHOOK", "")
HEALTH_INTERVAL = int(os.getenv("HEALTH_INTERVAL", "3600"))

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# 简易 session 管理
_sessions: dict[str, float] = {}
SESSION_TTL = 86400  # 24 小时


def _check_session(token: Optional[str]) -> bool:
    if not token or token not in _sessions:
        return False
    if time.time() - _sessions[token] > SESSION_TTL:
        _sessions.pop(token, None)
        return False
    return True


# ======== WAF 绕过：acw_sc__v2 纯计算 ========

XOR_KEY = "3000176000856006061501533003690027800375"
UNSBOX_TABLE = [
    0x0F, 0x23, 0x1D, 0x18, 0x21, 0x10, 0x01, 0x26,
    0x0A, 0x09, 0x13, 0x1F, 0x28, 0x1B, 0x16, 0x17,
    0x19, 0x0D, 0x06, 0x0B, 0x27, 0x12, 0x14, 0x08,
    0x0E, 0x15, 0x20, 0x1A, 0x02, 0x1E, 0x07, 0x04,
    0x11, 0x05, 0x03, 0x1C, 0x22, 0x25, 0x0C, 0x24,
]


def compute_acw_cookie(arg1: str) -> str:
    """从 arg1 计算 acw_sc__v2 cookie 值（unsbox 置换 + XOR）"""
    unsboxed = "".join(arg1[i - 1] for i in UNSBOX_TABLE)
    out = ""
    for i in range(0, 40, 2):
        a = int(unsboxed[i : i + 2], 16)
        b = int(XOR_KEY[i : i + 2], 16)
        out += format(a ^ b, "02x")
    return out


def extract_arg1(html: str) -> Optional[str]:
    """从 WAF challenge 页面提取 arg1"""
    m = re.search(r"var\s+arg1\s*=\s*'([0-9a-fA-F]{40})'", html)
    return m.group(1) if m else None


def merge_cookies(*sources: Optional[str]) -> str:
    """合并多个 cookie 字符串，同名后者覆盖"""
    pairs: dict[str, str] = {}
    for src in sources:
        if not src:
            continue
        for item in src.split(";"):
            item = item.strip()
            if "=" not in item:
                continue
            name = item.split("=", 1)[0].strip()
            if name:
                pairs[name] = item
    return "; ".join(pairs.values())


def extract_set_cookies(headers: httpx.Headers) -> str:
    """从响应头提取 Set-Cookie 的 name=value 部分"""
    pairs = []
    for val in headers.get_list("set-cookie"):
        part = val.split(";")[0].strip()
        if part:
            pairs.append(part)
    return "; ".join(pairs)


async def get_waf_cookies(client: httpx.AsyncClient, target_url: str) -> Optional[str]:
    """获取 WAF challenge cookies（acw_tc + cdn_sec_tc + 计算 acw_sc__v2）"""
    try:
        resp = await client.get(
            target_url,
            headers={"User-Agent": UA, "Accept": "text/html"},
            follow_redirects=False,
        )
        body = resp.text
        base_cookies = extract_set_cookies(resp.headers)
        arg1 = extract_arg1(body)
        if not arg1 and not base_cookies:
            return None
        acw_part = f"acw_sc__v2={compute_acw_cookie(arg1)}" if arg1 else ""
        return merge_cookies(base_cookies, acw_part)
    except Exception as e:
        logger.error(f"WAF cookie 获取失败: {e}")
        return None


async def query_balance(account: dict) -> dict:
    """查询单个账号的实时余额，含重试逻辑"""
    name = account["name"]
    session_val = account["session"]
    api_user = account["api_user"]
    target_url = f"{UPSTREAM}/api/user/self"

    async with httpx.AsyncClient(timeout=20, http2=True) as client:
        # 获取 WAF cookie（尝试两个端点）
        waf_cookies = None
        for endpoint in ["/api/user/self", "/api/user/sign_in"]:
            waf_cookies = await get_waf_cookies(client, f"{UPSTREAM}{endpoint}")
            if waf_cookies:
                break

        if not waf_cookies:
            return {"name": name, "success": False, "error": "WAF cookie 获取失败"}

        # 带 WAF + session cookie 查询
        full_cookie = merge_cookies(waf_cookies, f"session={session_val}")
        headers = {
            "User-Agent": UA,
            "Cookie": full_cookie,
            "Accept": "application/json, text/plain, */*",
            "New-Api-User": api_user,
            "Origin": UPSTREAM,
            "Referer": f"{UPSTREAM}/",
        }

        resp = await client.get(target_url, headers=headers)
        body = resp.text

        # 如果仍然命中 WAF，重试一次
        retry_arg1 = extract_arg1(body)
        if retry_arg1:
            logger.info(f"{name}: WAF 重试中...")
            retry_base = extract_set_cookies(resp.headers)
            retry_acw = f"acw_sc__v2={compute_acw_cookie(retry_arg1)}"
            retry_cookies = merge_cookies(waf_cookies, retry_base, retry_acw)
            full_cookie = merge_cookies(retry_cookies, f"session={session_val}")
            headers["Cookie"] = full_cookie

            resp = await client.get(target_url, headers=headers)
            body = resp.text
            if extract_arg1(body):
                return {"name": name, "success": False, "error": "WAF 重试后仍被拦截"}

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return {"name": name, "success": False, "error": f"非 JSON 响应: {body[:100]}"}

        if data.get("data"):
            user_data = data["data"]
            quota = user_data.get("quota", 0)
            used = user_data.get("used_quota", 0)
            _update_balance_cache(name, quota / 500000, used / 500000)
            return {
                "name": name,
                "success": True,
                "username": user_data.get("username", ""),
                "quota": quota,
                "used_quota": used,
                "balance_usd": round(quota / 500000, 2),
                "used_usd": round(used / 500000, 2),
            }
        else:
            msg = data.get("message", str(data))
            return {"name": name, "success": False, "error": msg}


# ======== 数据库操作 ========


def _init_db():
    """首次启动时自动创建表"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            provider TEXT NOT NULL DEFAULT 'anyrouter',
            auth_method TEXT NOT NULL DEFAULT 'cookie',
            cookies TEXT NOT NULL DEFAULT '',
            api_user TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT '',
            password TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            last_checkin TEXT,
            last_status TEXT,
            last_balance REAL,
            last_used REAL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            domain TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


def _migrate_db():
    """数据库迁移：添加新字段"""
    conn = sqlite3.connect(DB_PATH)
    columns = [row[1] for row in conn.execute("PRAGMA table_info(accounts)").fetchall()]
    if "api_key" not in columns:
        conn.execute("ALTER TABLE accounts ADD COLUMN api_key TEXT NOT NULL DEFAULT ''")
    if "last_health" not in columns:
        conn.execute("ALTER TABLE accounts ADD COLUMN last_health TEXT")
    if "health_status" not in columns:
        conn.execute("ALTER TABLE accounts ADD COLUMN health_status TEXT")
    conn.commit()
    conn.close()


def _get_accounts(include_disabled: bool = False) -> list[dict]:
    """从 SQLite 读取账号"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    where = "" if include_disabled else "WHERE enabled=1"
    rows = conn.execute(
        f"SELECT id, name, api_user, api_key, cookies, enabled, last_balance, last_used, last_checkin, last_status, last_health, health_status FROM accounts {where}"
    ).fetchall()
    conn.close()
    result = []
    for row in rows:
        cookies = json.loads(row["cookies"]) if row["cookies"] else {}
        result.append({
            "id": row["id"],
            "name": row["name"],
            "api_user": row["api_user"],
            "api_key": row["api_key"] if "api_key" in row.keys() else "",
            "session": cookies.get("session", ""),
            "has_session": bool(cookies.get("session")),
            "enabled": bool(row["enabled"]),
            "cached_balance": row["last_balance"],
            "cached_used": row["last_used"],
            "last_checkin": row["last_checkin"],
            "last_status": row["last_status"],
            "last_health": row["last_health"] if "last_health" in row.keys() else None,
            "health_status": row["health_status"] if "health_status" in row.keys() else None,
        })
    return result


def _add_account(name: str, api_user: str, session_val: str, api_key: str = "") -> bool:
    """新增账号"""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO accounts (name, provider, auth_method, cookies, api_user, api_key, enabled, created_at, updated_at) "
            "VALUES (?, 'anyrouter', 'cookie', ?, ?, ?, 1, datetime('now'), datetime('now'))",
            (name, json.dumps({"session": session_val}), api_user, api_key),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def _delete_account(name: str) -> bool:
    """删除账号"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("DELETE FROM accounts WHERE name=?", (name,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def _update_account(name: str, api_user: Optional[str] = None, session_val: Optional[str] = None, api_key: Optional[str] = None, enabled: Optional[bool] = None):
    """更新账号信息"""
    conn = sqlite3.connect(DB_PATH)
    if api_user is not None:
        conn.execute("UPDATE accounts SET api_user=?, updated_at=datetime('now') WHERE name=?", (api_user, name))
    if session_val is not None:
        row = conn.execute("SELECT cookies FROM accounts WHERE name=?", (name,)).fetchone()
        cookies = json.loads(row[0]) if row and row[0] else {}
        cookies["session"] = session_val
        conn.execute("UPDATE accounts SET cookies=?, updated_at=datetime('now') WHERE name=?", (json.dumps(cookies), name))
    if api_key is not None:
        conn.execute("UPDATE accounts SET api_key=?, updated_at=datetime('now') WHERE name=?", (api_key, name))
    if enabled is not None:
        conn.execute("UPDATE accounts SET enabled=?, updated_at=datetime('now') WHERE name=?", (1 if enabled else 0, name))
    conn.commit()
    conn.close()


def _update_balance_cache(name: str, balance: float, used: float):
    """更新 DB 中的余额缓存和最后查询时间"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "UPDATE accounts SET last_balance=?, last_used=?, last_checkin=datetime('now','localtime'), last_status='success', updated_at=datetime('now') WHERE name=?",
            (balance, used, name),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"更新余额缓存失败 {name}: {e}")


def _parse_auth(authorization: Optional[str]) -> tuple[bool, Optional[str]]:
    """解析 Bearer token：password:account_name 或 password"""
    if not authorization:
        return False, None
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False, None
    token = parts[1]
    if ":" in token:
        password, account_name = token.split(":", 1)
        return password == ADMIN_PASSWORD, account_name
    return token == ADMIN_PASSWORD, None


# ======== CC Switch 端点 ========


@app.get("/api/user/self")
async def get_user_self(authorization: Optional[str] = Header(None)):
    """CC Switch NewAPI 模板格式。API Key: password:account_name"""
    valid, account_name = _parse_auth(authorization)
    if not valid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not account_name:
        raise HTTPException(status_code=400, detail="需要指定账号 (password:account_name)")

    accounts = _get_accounts()
    target = next((a for a in accounts if a["name"] == account_name), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"账号 {account_name} 不存在")
    if not target["session"]:
        raise HTTPException(status_code=400, detail=f"账号 {account_name} 无 session cookie")

    result = await query_balance(target)

    if result["success"]:
        return {
            "success": True,
            "data": {
                "username": result.get("username", account_name),
                "quota": result["quota"],
                "used_quota": result["used_quota"],
            },
        }
    else:
        if target["cached_balance"] is not None:
            logger.warning(f"{account_name}: 实时查询失败({result['error']})，返回缓存值")
            return {
                "success": True,
                "data": {
                    "username": account_name,
                    "quota": int(target["cached_balance"] * 500000),
                    "used_quota": int((target["cached_used"] or 0) * 500000),
                },
            }
        raise HTTPException(status_code=502, detail=result["error"])


@app.get("/user/balance")
async def get_balance(authorization: Optional[str] = Header(None)):
    """CC Switch 通用模板格式"""
    valid, account_name = _parse_auth(authorization)
    if not valid:
        raise HTTPException(status_code=401, detail="Unauthorized")

    accounts = _get_accounts()
    if account_name:
        accounts = [a for a in accounts if a["name"] == account_name]
        if not accounts:
            raise HTTPException(status_code=404, detail="Account not found")

    total_balance = 0.0
    total_used = 0.0
    details = []

    for acc in accounts:
        if not acc["session"]:
            continue
        result = await query_balance(acc)
        if result["success"]:
            total_balance += result["balance_usd"]
            total_used += result["used_usd"]
            details.append(result)
        elif acc["cached_balance"] is not None:
            total_balance += acc["cached_balance"]
            total_used += acc["cached_used"] or 0

    return {
        "total_balance": round(total_balance, 2),
        "total_used": round(total_used, 2),
        "accounts": len(details),
    }


# ======== 管理后台 API ========


@app.post("/admin/login")
async def admin_login(request: Request):
    """管理后台登录"""
    form = await request.json()
    if form.get("password") != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="密码错误")
    token = secrets.token_hex(16)
    _sessions[token] = time.time()
    resp = JSONResponse({"success": True})
    resp.set_cookie("admin_token", token, httponly=True, max_age=SESSION_TTL, secure=True, samesite="none")
    return resp


@app.post("/admin/logout")
async def admin_logout(admin_token: Optional[str] = Cookie(None)):
    _sessions.pop(admin_token or "", None)
    resp = JSONResponse({"success": True})
    resp.delete_cookie("admin_token")
    return resp


@app.get("/admin/api/accounts")
async def admin_list_accounts(admin_token: Optional[str] = Cookie(None)):
    """列出所有账号及缓存余额"""
    if not _check_session(admin_token):
        raise HTTPException(status_code=401, detail="未登录")
    accounts = _get_accounts(include_disabled=True)
    for acc in accounts:
        acc.pop("session", None)
    return {"accounts": accounts}


@app.post("/admin/api/accounts")
async def admin_add_account(request: Request, admin_token: Optional[str] = Cookie(None)):
    """新增账号"""
    if not _check_session(admin_token):
        raise HTTPException(status_code=401, detail="未登录")
    data = await request.json()
    name = data.get("name", "").strip()
    api_user = data.get("api_user", "").strip()
    session_val = data.get("session", "").strip()
    api_key = data.get("api_key", "").strip()
    if not name or not api_user or not session_val:
        raise HTTPException(status_code=400, detail="name, api_user, session 均为必填")
    if not _add_account(name, api_user, session_val, api_key):
        raise HTTPException(status_code=409, detail="账号已存在")
    return {"success": True}


@app.put("/admin/api/accounts/{name}")
async def admin_update_account(name: str, request: Request, admin_token: Optional[str] = Cookie(None)):
    """更新账号"""
    if not _check_session(admin_token):
        raise HTTPException(status_code=401, detail="未登录")
    data = await request.json()
    _update_account(
        name,
        api_user=data.get("api_user"),
        session_val=data.get("session"),
        api_key=data.get("api_key"),
        enabled=data.get("enabled"),
    )
    return {"success": True}


@app.delete("/admin/api/accounts/{name}")
async def admin_delete_account(name: str, admin_token: Optional[str] = Cookie(None)):
    """删除账号"""
    if not _check_session(admin_token):
        raise HTTPException(status_code=401, detail="未登录")
    if not _delete_account(name):
        raise HTTPException(status_code=404, detail="账号不存在")
    return {"success": True}


@app.post("/admin/api/refresh/{name}")
async def admin_refresh_one(name: str, admin_token: Optional[str] = Cookie(None)):
    """刷新单个账号余额"""
    if not _check_session(admin_token):
        raise HTTPException(status_code=401, detail="未登录")
    accounts = _get_accounts(include_disabled=True)
    target = next((a for a in accounts if a["name"] == name), None)
    if not target or not target["session"]:
        raise HTTPException(status_code=404, detail="账号不存在或无 session")
    return await query_balance(target)


@app.post("/admin/api/refresh")
async def admin_refresh_all(admin_token: Optional[str] = Cookie(None)):
    """刷新所有启用账号的余额"""
    if not _check_session(admin_token):
        raise HTTPException(status_code=401, detail="未登录")
    accounts = _get_accounts()
    results = []
    for acc in accounts:
        if acc["session"]:
            results.append(await query_balance(acc))
    return {"results": results}


# ======== 测活 + 飞书通知 ========


async def health_check_account(name: str, api_key: str) -> dict:
    """测活：先验证 API Key 有效性，再尝试发送 Claude 请求"""
    if not RELAY_URL:
        return {"name": name, "success": False, "error": "未配置 RELAY_URL"}
    if not api_key:
        return {"name": name, "success": False, "error": "未配置 API Key"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # 第一步：验证 API Key 有效（GET /v1/models）
            resp = await client.get(
                f"{RELAY_URL}/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            if resp.status_code == 401:
                return {"name": name, "success": False, "error": "API Key 无效或已过期"}
            if resp.status_code != 200:
                return {"name": name, "success": False, "error": f"Key 验证失败: HTTP {resp.status_code}"}

            # 第二步：尝试实际发送消息（带 1M 上下文 beta header）
            msg_resp = await client.post(
                f"{RELAY_URL}/v1/messages",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "anthropic-beta": "context-1m-2025-08-07",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 50,
                    "messages": [{"role": "user", "content": "show me the money"}],
                },
            )
            if msg_resp.status_code == 200:
                data = msg_resp.json()
                text = ""
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        text = block.get("text", "")[:100]
                        break
                return {"name": name, "success": True, "detail": f"消息成功: {text}"}
            else:
                # Key 有效但消息受限（如需启用 1M），仍算存活
                body = msg_resp.text[:200]
                return {"name": name, "success": True, "detail": f"Key 有效, 消息受限: {body}"}
    except Exception as e:
        return {"name": name, "success": False, "error": str(e)}


def _update_health_status(name: str, success: bool, error: str = ""):
    """更新测活状态"""
    try:
        conn = sqlite3.connect(DB_PATH)
        status = "alive" if success else f"dead:{error}"
        conn.execute(
            "UPDATE accounts SET health_status=?, last_health=datetime('now','localtime'), updated_at=datetime('now') WHERE name=?",
            (status, name),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"更新测活状态失败 {name}: {e}")


async def send_feishu_notification(results: list):
    """发送飞书 Webhook 通知"""
    if not FEISHU_WEBHOOK or not results:
        return

    alive = [r for r in results if r["success"]]
    dead = [r for r in results if not r["success"]]

    if not alive:
        return

    lines = [f"**✅ 存活账号 ({len(alive)})**\n"]
    for r in alive:
        lines.append(f"- **{r['name']}**: 正常")
    if dead:
        lines.append(f"\n**❌ 失效账号 ({len(dead)})**")
        for r in dead:
            lines.append(f"- **{r['name']}**: {r.get('error', '未知错误')}")

    card = {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"content": "🔍 账号测活报告", "tag": "plain_text"},
                "template": "green" if not dead else "orange",
            },
            "elements": [
                {"tag": "div", "text": {"tag": "lark_md", "content": "\n".join(lines)}},
                {"tag": "div", "text": {"tag": "plain_text", "content": f"检查时间: {time.strftime('%Y-%m-%d %H:%M:%S')}"}},
            ],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(FEISHU_WEBHOOK, json=card)
    except Exception as e:
        logger.error(f"飞书通知发送失败: {e}")


async def run_health_check_all() -> list:
    """执行所有账号测活"""
    accounts = _get_accounts()
    targets = [a for a in accounts if a["api_key"]]
    if not targets:
        logger.info("无配置 api_key 的账号，跳过测活")
        return []

    results = []
    for acc in targets:
        result = await health_check_account(acc["name"], acc["api_key"])
        results.append(result)
        _update_health_status(acc["name"], result["success"], result.get("error", ""))

    alive_count = sum(1 for r in results if r["success"])
    logger.info(f"测活完成: {alive_count}/{len(results)} 存活")

    await send_feishu_notification(results)
    return results


async def _health_check_loop():
    """后台测活循环"""
    await asyncio.sleep(60)  # 启动后等待 60 秒再开始第一次
    while True:
        try:
            await run_health_check_all()
        except Exception as e:
            logger.error(f"测活循环异常: {e}")
        await asyncio.sleep(HEALTH_INTERVAL)


@app.post("/admin/api/health-check")
async def admin_health_check(admin_token: Optional[str] = Cookie(None)):
    """手动触发测活"""
    if not _check_session(admin_token):
        raise HTTPException(status_code=401, detail="未登录")
    results = await run_health_check_all()
    return {"results": results}


# ======== 管理界面 HTML ========

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AnyRouter Balance</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{background:#1e293b;padding:2rem;border-radius:12px;width:320px;box-shadow:0 4px 24px rgba(0,0,0,.3)}
.login-box h2{text-align:center;margin-bottom:1.5rem;color:#60a5fa}
.login-box input{width:100%;padding:.7rem;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#e2e8f0;margin-bottom:1rem;font-size:.95rem}
.login-box button{width:100%;padding:.7rem;border:none;border-radius:8px;background:#3b82f6;color:#fff;font-size:1rem;cursor:pointer;transition:background .2s}
.login-box button:hover{background:#2563eb}
.container{max-width:960px;margin:0 auto;padding:1.5rem}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;flex-wrap:wrap;gap:.5rem}
header h1{font-size:1.4rem;color:#60a5fa}
.btn{padding:.45rem .9rem;border:none;border-radius:6px;cursor:pointer;font-size:.85rem;transition:all .2s}
.btn-primary{background:#3b82f6;color:#fff}.btn-primary:hover{background:#2563eb}
.btn-danger{background:#ef4444;color:#fff}.btn-danger:hover{background:#dc2626}
.btn-success{background:#10b981;color:#fff}.btn-success:hover{background:#059669}
.btn-ghost{background:transparent;color:#94a3b8;border:1px solid #334155}.btn-ghost:hover{background:#1e293b}
.btn-sm{padding:.3rem .6rem;font-size:.8rem}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem}
.stat-card{background:#1e293b;border-radius:10px;padding:1.2rem;text-align:center}
.stat-card .label{font-size:.8rem;color:#94a3b8;margin-bottom:.3rem}
.stat-card .value{font-size:1.6rem;font-weight:700;color:#34d399}
.stat-card .value.used{color:#fb923c}
.stat-card .value.count{color:#60a5fa}
table{width:100%;border-collapse:separate;border-spacing:0;background:#1e293b;border-radius:10px;overflow:hidden}
th{background:#334155;padding:.7rem .8rem;text-align:left;font-size:.8rem;color:#94a3b8;font-weight:600;text-transform:uppercase}
td{padding:.65rem .8rem;border-top:1px solid #1e293b;font-size:.9rem}
tr:hover td{background:#262f3f}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:600}
.badge-ok{background:#064e3b;color:#34d399}
.badge-err{background:#450a0a;color:#fca5a5}
.badge-off{background:#1e293b;color:#64748b;border:1px solid #334155}
.actions{display:flex;gap:.4rem}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:50;display:none}
.modal-overlay.active{display:flex}
.modal{background:#1e293b;border-radius:12px;padding:1.5rem;width:420px;max-width:90vw}
.modal h3{margin-bottom:1rem;color:#60a5fa}
.modal label{display:block;font-size:.8rem;color:#94a3b8;margin-bottom:.3rem;margin-top:.8rem}
.modal input,.modal textarea{width:100%;padding:.55rem;border:1px solid #334155;border-radius:6px;background:#0f172a;color:#e2e8f0;font-size:.9rem;font-family:monospace}
.modal textarea{min-height:60px;resize:vertical}
.modal-footer{display:flex;justify-content:flex-end;gap:.5rem;margin-top:1.2rem}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #334155;border-top-color:#3b82f6;border-radius:50%;animation:spin .6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.msg{padding:.6rem 1rem;border-radius:6px;margin-bottom:1rem;font-size:.85rem;display:none}
.msg.ok{display:block;background:#064e3b;color:#34d399}
.msg.err{display:block;background:#450a0a;color:#fca5a5}
@media(max-width:640px){.stats{grid-template-columns:1fr}.container{padding:1rem}}
</style>
</head>
<body>

<div id="loginPage" class="login-wrap">
  <div class="login-box">
    <h2>AnyRouter Balance</h2>
    <div id="loginMsg" class="msg"></div>
    <input id="loginPwd" type="password" placeholder="管理密码" autofocus>
    <button onclick="doLogin()">登录</button>
  </div>
</div>

<div id="mainPage" style="display:none">
  <div class="container">
    <header>
      <h1>AnyRouter Balance</h1>
      <div style="display:flex;gap:.5rem;flex-wrap:wrap">
        <button class="btn btn-success" onclick="refreshAll()">刷新全部余额</button>
        <button class="btn btn-success" onclick="healthCheckAll()" style="background:#8b5cf6">测活全部</button>
        <button class="btn btn-primary" onclick="showAddModal()">添加账号</button>
        <button class="btn btn-ghost" onclick="doLogout()">退出</button>
      </div>
    </header>
    <div id="globalMsg" class="msg"></div>
    <div class="stats">
      <div class="stat-card"><div class="label">总余额</div><div id="totalBal" class="value">--</div></div>
      <div class="stat-card"><div class="label">总消耗</div><div id="totalUsed" class="value used">--</div></div>
      <div class="stat-card"><div class="label">账号数</div><div id="totalCount" class="value count">--</div></div>
    </div>
    <table>
      <thead><tr><th>账号</th><th>余额</th><th>已用</th><th>余额状态</th><th>测活状态</th><th>最后更新</th><th>操作</th></tr></thead>
      <tbody id="accountsBody"><tr><td colspan="6" style="text-align:center;color:#64748b">加载中...</td></tr></tbody>
    </table>
    <div style="margin-top:1.5rem;padding:1rem;background:#1e293b;border-radius:10px;font-size:.85rem;color:#94a3b8;line-height:1.8">
      <div style="color:#60a5fa;font-weight:600;font-size:.95rem;margin-bottom:.5rem">CC Switch 配置说明</div>
      <div>1. 模板选择 <b style="color:#e2e8f0">NewAPI</b></div>
      <div>2. Base URL: <code id="ccBaseUrl2" style="color:#34d399;background:#0f172a;padding:.15rem .4rem;border-radius:4px">-</code></div>
      <div>3. API Key: <code style="color:#34d399;background:#0f172a;padding:.15rem .4rem;border-radius:4px">密码:账号名称</code></div>
      <div style="margin-top:.4rem;color:#64748b">示例: 密码为 <code style="color:#fb923c">abc123</code>，账号为 <code style="color:#fb923c">myaccount</code>，则 API Key 填 <code style="color:#fb923c">abc123:myaccount</code></div>
    </div>
  </div>
</div>

<div id="modalOverlay" class="modal-overlay">
  <div class="modal">
    <h3 id="modalTitle">添加账号</h3>
    <div id="modalMsg" class="msg"></div>
    <label>账号名称</label>
    <input id="mName" placeholder="如 myaccount">
    <label>API User ID</label>
    <input id="mApiUser" placeholder="登录后访问 /api/user/self 获取 data.id">
    <label>Session Cookie</label>
    <textarea id="mSession" placeholder="浏览器 F12 → Cookies → session 的值"></textarea>
    <label>API Key（测活用，sk-xxx）</label>
    <input id="mApiKey" placeholder="留空则不参与测活">
    <div style="margin-top:1rem;padding:.8rem;background:#0f172a;border-radius:6px;font-size:.8rem;color:#94a3b8;line-height:1.6">
      <div style="color:#60a5fa;font-weight:600;margin-bottom:.4rem">CC Switch 配置说明</div>
      <div>1. 模板选择 <b style="color:#e2e8f0">NewAPI</b></div>
      <div>2. Base URL: <code id="ccBaseUrl" style="color:#34d399;background:#1e293b;padding:0 .3rem;border-radius:3px">-</code></div>
      <div>3. API Key: <code style="color:#34d399;background:#1e293b;padding:0 .3rem;border-radius:3px">密码:账号名称</code></div>
      <div style="margin-top:.3rem;color:#64748b">示例: 密码为 <code style="color:#fb923c">abc123</code>，账号为 <code style="color:#fb923c">myaccount</code>，则 API Key 填 <code style="color:#fb923c">abc123:myaccount</code></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeModal()">取消</button>
      <button class="btn btn-primary" id="modalSubmit" onclick="submitAccount()">添加</button>
    </div>
  </div>
</div>

<script>
const API = '';
let editingName = null;
const F = (url, opts) => fetch(url, {...opts, credentials: 'include'});

async function doLogin() {
  const pwd = document.getElementById('loginPwd').value;
  const res = await F(API + '/admin/login', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: pwd})
  });
  if (res.ok) {
    document.getElementById('loginPage').style.display = 'none';
    document.getElementById('mainPage').style.display = 'block';
    loadAccounts().then(function() { refreshAll(); });
  } else {
    showMsg('loginMsg', '密码错误', true);
  }
}
document.getElementById('loginPwd').addEventListener('keydown', function(e) { if(e.key==='Enter') doLogin(); });

async function doLogout() {
  await F(API + '/admin/logout', {method: 'POST'});
  location.reload();
}

async function loadAccounts() {
  const res = await F(API + '/admin/api/accounts');
  if (res.status === 401) {
    document.getElementById('loginPage').style.display = '';
    document.getElementById('mainPage').style.display = 'none';
    return;
  }
  var bu = document.getElementById('ccBaseUrl2');
  if (bu) bu.textContent = location.origin;
  const data = await res.json();
  const accounts = data.accounts || [];
  const tbody = document.getElementById('accountsBody');
  let totalBal = 0, totalUsed = 0;

  if (accounts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#64748b">暂无账号，点击"添加账号"开始</td></tr>';
  } else {
    tbody.innerHTML = accounts.map(function(a) {
      const bal = a.cached_balance != null ? a.cached_balance : 0;
      const used = a.cached_used != null ? a.cached_used : 0;
      totalBal += a.enabled ? bal : 0;
      totalUsed += a.enabled ? used : 0;
      const statusBadge = !a.enabled
        ? '<span class="badge badge-off">停用</span>'
        : !a.has_session
        ? '<span class="badge badge-err">无Cookie</span>'
        : a.last_status === 'success'
        ? '<span class="badge badge-ok">正常</span>'
        : '<span class="badge badge-err">' + (a.last_status || '未知') + '</span>';
      var hs = a.health_status || '';
      var healthBadge = !a.api_key
        ? '<span class="badge badge-off">未配置Key</span>'
        : hs.startsWith('alive')
        ? '<span class="badge badge-ok">存活</span>'
        : hs.startsWith('dead')
        ? '<span class="badge badge-err">失效</span>'
        : '<span class="badge badge-off">未检测</span>';
      var healthTime = a.last_health ? a.last_health.replace('T',' ').substring(5,16) : '-';
      const lastTime = a.last_checkin ? a.last_checkin.replace('T',' ').substring(5,16) : '-';
      return '<tr>'
        + '<td><b>' + esc(a.name) + '</b><br><small style="color:#64748b">ID: ' + esc(a.api_user) + '</small></td>'
        + '<td style="color:#34d399;font-weight:600">$' + bal.toFixed(2) + '</td>'
        + '<td style="color:#fb923c">$' + used.toFixed(2) + '</td>'
        + '<td>' + statusBadge + '</td>'
        + '<td>' + healthBadge + '<br><small style="color:#64748b;font-size:.7rem">' + healthTime + '</small></td>'
        + '<td style="color:#94a3b8;font-size:.8rem">' + lastTime + '</td>'
        + '<td><div class="actions">'
        + '<button class="btn btn-primary btn-sm" data-action="refresh" data-name="' + esc(a.name) + '">刷新</button>'
        + '<button class="btn btn-ghost btn-sm" data-action="edit" data-name="' + esc(a.name) + '" data-apiuser="' + esc(a.api_user) + '" data-apikey="' + esc(a.api_key || '') + '" data-enabled="' + a.enabled + '">编辑</button>'
        + '<button class="btn btn-danger btn-sm" data-action="delete" data-name="' + esc(a.name) + '">删除</button>'
        + '</div></td></tr>';
    }).join('');
  }

  document.getElementById('totalBal').textContent = '$' + totalBal.toFixed(2);
  document.getElementById('totalUsed').textContent = '$' + totalUsed.toFixed(2);
  document.getElementById('totalCount').textContent = accounts.filter(function(a){return a.enabled}).length;
}

// 事件委托处理表格按钮
document.getElementById('accountsBody').addEventListener('click', function(e) {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;
  const name = btn.dataset.name;
  if (action === 'refresh') refreshOne(name, btn);
  else if (action === 'edit') editAccount(name, btn.dataset.apiuser, btn.dataset.enabled === 'true', btn.dataset.apikey || '');
  else if (action === 'delete') deleteAccount(name);
});

async function refreshOne(name, btn) {
  const orig = btn.innerHTML;
  btn.innerHTML = '<span class="spinner"></span>';
  btn.disabled = true;
  try {
    const res = await F(API + '/admin/api/refresh/' + encodeURIComponent(name), {method: 'POST'});
    const data = await res.json();
    if (data.success) showMsg('globalMsg', name + ': $' + data.balance_usd, false);
    else showMsg('globalMsg', name + ': ' + (data.error || '查询失败'), true);
    await loadAccounts();
  } finally {
    btn.innerHTML = orig;
    btn.disabled = false;
  }
}

async function refreshAll() {
  showMsg('globalMsg', '正在刷新所有账号...', false);
  const res = await F(API + '/admin/api/refresh', {method: 'POST'});
  const data = await res.json();
  const results = data.results || [];
  const ok = results.filter(function(r){return r.success}).length;
  showMsg('globalMsg', '刷新完成: ' + ok + '/' + results.length + ' 成功', ok < results.length);
  await loadAccounts();
}

function showAddModal() {
  editingName = null;
  document.getElementById('modalTitle').textContent = '添加账号';
  document.getElementById('modalSubmit').textContent = '添加';
  document.getElementById('mName').value = '';
  document.getElementById('mName').disabled = false;
  document.getElementById('mApiUser').value = '';
  document.getElementById('mSession').value = '';
  document.getElementById('mSession').placeholder = '浏览器 F12 → Cookies → session 的值';
  document.getElementById('mApiKey').value = '';
  document.getElementById('ccBaseUrl').textContent = location.origin;
  document.getElementById('modalMsg').className = 'msg';
  document.getElementById('modalOverlay').classList.add('active');
}

function editAccount(name, apiUser, enabled, apiKey) {
  editingName = name;
  document.getElementById('modalTitle').textContent = '编辑 ' + name;
  document.getElementById('modalSubmit').textContent = '保存';
  document.getElementById('mName').value = name;
  document.getElementById('mName').disabled = true;
  document.getElementById('mApiUser').value = apiUser;
  document.getElementById('mSession').value = '';
  document.getElementById('mSession').placeholder = '留空不修改 session';
  document.getElementById('mApiKey').value = apiKey || '';
  document.getElementById('ccBaseUrl').textContent = location.origin;
  document.getElementById('modalMsg').className = 'msg';
  document.getElementById('modalOverlay').classList.add('active');
}

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('active');
}

async function submitAccount() {
  const name = document.getElementById('mName').value.trim();
  const apiUser = document.getElementById('mApiUser').value.trim();
  const session = document.getElementById('mSession').value.trim();
  const apiKey = document.getElementById('mApiKey').value.trim();

  if (editingName) {
    const body = {api_user: apiUser, api_key: apiKey};
    if (session) body.session = session;
    const res = await F(API + '/admin/api/accounts/' + encodeURIComponent(editingName), {
      method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
    });
    if (res.ok) { closeModal(); await loadAccounts(); showMsg('globalMsg', editingName + ' 已更新', false); }
    else { const d = await res.json(); showMsg('modalMsg', d.detail || '更新失败', true); }
  } else {
    if (!name || !apiUser || !session) { showMsg('modalMsg', '所有字段均为必填', true); return; }
    const res = await F(API + '/admin/api/accounts', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name: name, api_user: apiUser, session: session, api_key: apiKey})
    });
    if (res.ok) { closeModal(); await loadAccounts(); showMsg('globalMsg', name + ' 已添加', false); }
    else { const d = await res.json(); showMsg('modalMsg', d.detail || '添加失败', true); }
  }
}

async function deleteAccount(name) {
  if (!confirm('确定删除 ' + name + '？')) return;
  const res = await F(API + '/admin/api/accounts/' + encodeURIComponent(name), {method: 'DELETE'});
  if (res.ok) { await loadAccounts(); showMsg('globalMsg', name + ' 已删除', false); }
}

async function healthCheckAll() {
  showMsg('globalMsg', '正在测活...', false);
  const res = await F(API + '/admin/api/health-check', {method: 'POST'});
  const data = await res.json();
  const results = data.results || [];
  const alive = results.filter(function(r){return r.success}).length;
  showMsg('globalMsg', '测活完成: ' + alive + '/' + results.length + ' 存活', alive < results.length);
  await loadAccounts();
}

function showMsg(id, text, isErr) {
  var el = document.getElementById(id);
  el.textContent = text;
  el.className = 'msg ' + (isErr ? 'err' : 'ok');
  if (id !== 'modalMsg') setTimeout(function() { el.className = 'msg'; }, 5000);
}

function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

F(API + '/admin/api/accounts').then(function(r) {
  if (r.ok) {
    document.getElementById('loginPage').style.display = 'none';
    document.getElementById('mainPage').style.display = 'block';
    loadAccounts().then(function() { refreshAll(); });
  }
});
</script>
</body>
</html>"""


@app.get("/")
async def dashboard():
    """管理后台首页"""
    return HTMLResponse(DASHBOARD_HTML)


@app.on_event("startup")
async def startup():
    _init_db()
    _migrate_db()
    if RELAY_URL:
        asyncio.create_task(_health_check_loop())


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
