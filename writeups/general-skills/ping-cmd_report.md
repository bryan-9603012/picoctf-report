## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Web Exploitation
- **Difficulty:** Easy
- **Author:** Bryan
- **Date:** 2026-3-27

## 一、基本資訊

**題目名稱：** ping-cmd  
**題目類型：** Web Exploitation  
**平台：** picoCTF 2026  
**目標：** 利用輸入驗證缺陷讓伺服器洩漏 flag.txt 內容

## 二、題目概述

本題提供一個 nc 互動服務，要求使用者輸入 IP 位址，伺服器會代為執行 ping 測試。題目敘述中提到系統似乎只能 ping Google DNS 8.8.8.8，但又暗示玩家可以對輸入內容發揮創意。

本題的核心並不在於網路連通性，而是在於：

- 觀察服務如何使用使用者輸入
- 判斷後端是否直接將輸入拼接到 shell 指令
- 嘗試命令串接與指令注入
- 利用命令注入直接讀取 flag.txt

## 三、分析目標

本次分析的主要目標如下：

- 確認服務基本功能
- 判斷是否存在 OS Command Injection
- 設計可行 payload
- 成功讀取 flag.txt
- 說明漏洞成因與防禦方法

## 四、環境觀察

連線至 nc 服務後，系統會提示：

Enter an IP address to ping! (We have tight security because we only allow '8.8.8.8')

輸入 8.8.8.8 後，系統正常回傳 ping 結果。

**觀察結果**

- 後端確實會執行 ping
- 題目刻意強調 only allow 8.8.8.8
- 描述中出現 get a little creative with your input，暗示輸入可能未被妥善過濾

## 五、弱點分析：OS Command Injection

### 5.1 弱點描述

後端大概率將使用者輸入直接拼接進 shell 命令，例如：

ping -c 2 <user_input>

若沒有正確過濾 shell metacharacters，則攻擊者可透過：

;
&&
|
$(...)

t等符號，額外執行任意系統命令。

### 5.2 弱點成因

- 使用者輸入直接進入 shell
- 僅做表面字串限制，而非嚴格參數驗證
- 未使用安全的 process invocation 方式
- 對 shell 控制字元缺乏過濾

### 5.3 安全意義

這類漏洞若出現在真實系統中，可能導致：

- 任意命令執行
- 檔案讀取
- 機敏資料外洩
- 伺服器被完全接管

## 六、攻擊思路

本題利用鏈如下：

- 先以正常值 8.8.8.8 測試服務行為
- → 判斷輸入可能被直接拼進 ping 指令
- → 使用 shell command separator 串接額外命令
- → 先測試 ls 確認注入成立
- → 直接以 cat flag.txt 讀取旗標

## 七、利用過程

### 7.1 正常輸入測試

輸入：

8.8.8.8

系統會正常回傳 ping 結果，證明後端確實執行 ping。

### 7.2 注入測試

使用：

8.8.8.8;ls

若命令成功被分號切開，則 ping 完成後會接著執行 ls。

### 7.3 讀取 flag

確認可注入後，直接使用：

8.8.8.8;cat flag.txt

### 7.4 利用結果

服務回傳 flag 內容，成功證明後端存在 OS command injection。

## 八、利用結果

取得的 flag：

picoCTF{p1nG_c0mm@nd_3xpL0it_su33essFuL_252214ae}

## 九、完整 exploit 指令

```sh
8.8.8.8;cat flag.txt
```

## 十、成因分析

### 10.1 直接拼接 shell 指令

若應用程式以字串拼接方式建構系統命令，且將使用者輸入直接帶入，即會形成命令注入風險。

### 10.2 驗證邏輯不足

系統雖聲稱 only allow 8.8.8.8，但實際上未阻止：

8.8.8.8;cat flag.txt

這類帶有 shell 分隔符的內容。

### 10.3 未遵守最小功能原則

若只是要執行 ping，應直接使用安全 API 並限制參數，而不是交給 shell 解釋整串字串。

## 十一、防禦建議

### 11.1 避免透過 shell 執行使用者可控輸入

應使用不經 shell 的系統呼叫，例如安全的 subprocess 參數列表模式。

### 11.2 嚴格驗證輸入格式

若只允許 IP，應使用正規表達式或 IP parser 驗證，不允許任何額外符號。

### 11.3 最小權限執行

即便出現漏洞，也應讓程式以最低權限執行，降低 flag 或系統檔案被讀取的風險。

## 使用工具

- nc
- ping
- shell metacharacters
- command injection
