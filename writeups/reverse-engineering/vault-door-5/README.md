## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-4-12

## 一、基本資訊

- **題目名稱：** vault-door-5
- **題目類型：** Reverse Engineering
- **平台：** picoCTF 2019
- **目標：** 還原正確密碼並通過 Vault Door 驗證

## 二、題目概述

本題提供一份 `VaultDoor5.java` 原始碼。程式會將輸入字串先做 URL encode，再將 URL encode 後的結果做 Base64 encode，最後與題目內建的 `expected` 字串比較。

表面上題目看起來像是在做某種較複雜的加密驗證，但實際分析後可發現，這只是兩層可逆編碼的組合。因此只要將流程反向執行，即可直接還原出原始 password。

## 三、分析目標

本次分析的主要目標如下：

1. 確認 `checkPassword()` 的驗證邏輯
2. 釐清 URL encode 與 Base64 encode 的正向流程
3. 反向解碼 `expected`
4. 還原原始 password
5. 說明此題的核心是雙層可逆編碼而非真正加密

## 四、靜態分析

題目核心程式如下：

```java
public boolean checkPassword(String password) {
    String urlEncoded = urlEncode(password.getBytes());
    String base64Encoded = base64Encode(urlEncoded.getBytes());
    String expected = "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm"
                    + "JTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2"
                    + "JTM0JTVmJTM3JTY2JTM4JTM1JTM1JTY2JTYzJTM1";
    return base64Encoded.equals(expected);
}
```

由上述邏輯可知，驗證流程其實是：

```text
password -> URL encode -> Base64 encode -> 與 expected 比較
```

因此逆向時只要反過來：

```text
expected -> Base64 decode -> URL decode -> 原始 password
```

## 五、弱點判定

### 5.1 題目本質描述

本題並非傳統漏洞利用題，而是一題典型的雙層編碼逆向題。其核心不是突破保護機制，而是找出：

- 程式對 password 做了哪些轉換
- 這些轉換是否可逆
- 如何將 `expected` 反解回原始 password

### 5.2 核心技術點

- Base64 reverse
- URL decode reverse
- Multi-layer reversible encoding
- Reverse Engineering by code inspection

### 5.3 風險說明

若這種設計被誤認為安全機制，會造成錯誤的安全感。Base64 與 URL encode 都是可逆的表示方式，不具備真正加密強度。只要攻擊者理解流程，就能直接反推出密碼內容。

## 六、攻擊思路

原始驗證流程如下：

```text
password -> URL encode -> Base64 encode -> expected
```

因此逆向思路為：

```text
已知 expected
=> Base64 decode
=> 得到 URL encoded 字串
=> URL decode
=> 還原原始 password
```

## 七、利用過程

### 7.1 Base64 解碼

將 `expected` 做 Base64 解碼後，可得：

```text
%63%30%6e%76%33%72%74%31%6e%67%5f%66%72%30%6d%5f%62%61%35%65%5f%36%34%5f%37%66%38%35%35%66%63%35
```

### 7.2 URL decode

將上述 `%xx` 十六進位表示法還原後，可得：

```text
c0nv3rt1ng_fr0m_ba5e_64_7f855fc5
```

### 7.3 包回 picoCTF 格式

```text
picoCTF{c0nv3rt1ng_fr0m_ba5e_64_7f855fc5}
```

## 八、利用結果

成功還原出正確 password，並得到 flag：

```text
picoCTF{c0nv3rt1ng_fr0m_ba5e_64_7f855fc5}
```

## 九、完整驗證腳本

```python
import base64
import urllib.parse

s = "JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVmJTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2JTM0JTVmJTM3JTY2JTM4JTM1JTM1JTY2JTYzJTM1"
x = base64.b64decode(s).decode()
password = urllib.parse.unquote(x)

print(x)
print(password)
print(f"picoCTF{{{password}}}")
```

## 十、成因分析

本題能被快速還原的主要原因，在於題目採用了兩層皆可逆的編碼方式來保護密碼。

問題點如下：

1. 使用可逆編碼而非真正加密
   - Base64 與 URL encode 只能改變表示形式，不能提供真正保護。
2. 驗證流程完整暴露在程式中
   - 攻擊者可以直接依程式邏輯反向解碼。
3. `expected` 直接內嵌在程式中
   - 只要取得該字串，就能做完整逆推。

## 十一、防禦建議

若在真實系統中要避免此類問題，可採取以下措施：

### 11.1 不要將可逆編碼視為安全機制

Base64、URL encode、Hex encode 都只是表示方式轉換，無法保護敏感資訊。

### 11.2 避免將完整轉換流程與密文同時暴露

只要流程與資料都能被讀到，攻擊者就能完整反向求解。

### 11.3 使用真正的安全驗證機制

若要保護密碼或敏感資料，應採用不可逆或伺服端驗證方式，而不是簡單的編碼堆疊。

## 十二、結論

Vault Door 5 是一題典型的雙層可逆編碼逆向題。透過閱讀 `checkPassword()` 可發現，程式只是先將 password 做 URL encode，再將結果做 Base64 encode，最後與固定字串比較。由於兩層轉換都可逆，因此只要按照相反順序還原，就能直接取得原始 password。

此題說明了一個重要觀念：把多個可逆編碼堆疊起來，並不等於真正的安全設計。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題目核心 | Base64 + URL reverse |
| 驗證條件 | `Base64(URLencode(password)) == expected` |
| 反推方式 | `expected -> Base64 decode -> URL decode` |
| 利用條件 | 可讀取程式碼或逆向驗證邏輯 |
| 攻擊效果 | 直接還原正確密碼 |
| 本題成果 | 成功取得 `picoCTF{c0nv3rt1ng_fr0m_ba5e_64_7f855fc5}` |

## 使用工具

- Java source code inspection
- Python
- Base64 decode
- URL decode
