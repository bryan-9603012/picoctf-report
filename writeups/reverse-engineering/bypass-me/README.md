## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-30

## 一、基本資訊

- **題目名稱：** Bypass Me
- **題目類型：** Reverse Engineering
- **平台：** picoCTF 2026
- **目標：** 繞過驗證邏輯並取得隱藏 flag

## 二、題目概述

本題提供一個需透過 SSH 登入遠端環境後執行的 binary `bypassme.bin`。題目明示不需要硬猜密碼，而是應透過 reverse engineering 與 debugger 分析驗證流程，找出真實密碼或直接繞過驗證。

實際分析後可發現，程式會先對使用者輸入進行 sanitize，再透過內部函式解碼出一組正確字串，最後以兩者進行比對。也就是說，本題的核心不是暴力破解，而是理解程式如何生成驗證字串。

## 三、分析目標

本次分析的主要目標如下：

1. 進入遠端環境並取得 `bypassme.bin`
2. 確認 binary 的保護與除錯資訊狀態
3. 找出關鍵函式與驗證流程
4. 還原程式內部隱藏的密碼
5. 成功取得 flag 並說明弱點成因

## 四、環境觀察

首先透過題目提供的 SSH 資訊登入遠端主機，確認目錄內存在目標檔案：

```bash
ssh ctf-player@foggy-cliff.picoctf.net -p 61945
ls -la
file bypassme.bin
```

觀察結果如下：

- `bypassme.bin` 為 **setuid ELF 64-bit**
- binary **帶有 debug info**
- binary **not stripped**

這代表本題非常適合直接使用 LLDB 下斷點並觀察 source-level / symbol-level 資訊。

## 五、靜態分析

先以 `strings` 搜尋關鍵字串：

```bash
strings bypassme.bin | grep -Ei "pass|sanit|auth|special|flag|denied|access|grant|correct|wrong"
```

可見到以下重要符號與字串：

- `Sanitized Input:[%s]`
- `Hint: Input must match something special...`
- `decode_password`
- `sanitize`
- `auth_sequence`
- `.../root/flag.txt`

由此可推測程式流程大致如下：

1. 讀取輸入
2. 對輸入做 sanitize
3. 透過 `decode_password()` 產生正確字串
4. 於 `auth_sequence()` 或主流程中完成比對
5. 成功後讀出 flag

## 六、動態分析

### 6.1 使用 LLDB 設定斷點

由於 binary 未 strip 且含 debug symbols，可直接以下斷點：

```bash
lldb ./bypassme.bin
```

```lldb
b main
b sanitize
b decode_password
b auth_sequence
run
```

程式成功停在 `decode_password(char *out)`，表示此函式即為解題核心。

### 6.2 觀察解碼流程

在 `decode_password()` 中進一步查看區域變數與反組譯：

```lldb
frame variable enc
memory read --format x --size 1 --count 11 &enc
disassemble --frame
```

可得編碼陣列：

```text
f9 df da cf d8 f9 cf c9 df d8 cf
```

而核心反組譯為：

```asm
movzbl -0x13(%rbp,%rax), %eax
xorl   $-0x56, %eax
...
movb   %dl, (%rax)
```

這代表邏輯可還原為：

```c
out[i] = enc[i] ^ 0xAA;
```

因為 `-0x56` 的低 8 位元即為 `0xAA`。

## 七、密碼還原

逐 byte XOR `0xAA`：

- `0xf9 ^ 0xaa = 0x53` → `S`
- `0xdf ^ 0xaa = 0x75` → `u`
- `0xda ^ 0xaa = 0x70` → `p`
- `0xcf ^ 0xaa = 0x65` → `e`
- `0xd8 ^ 0xaa = 0x72` → `r`
- `0xf9 ^ 0xaa = 0x53` → `S`
- `0xcf ^ 0xaa = 0x65` → `e`
- `0xc9 ^ 0xaa = 0x63` → `c`
- `0xdf ^ 0xaa = 0x75` → `u`
- `0xd8 ^ 0xaa = 0x72` → `r`
- `0xcf ^ 0xaa = 0x65` → `e`

得到正確字串：

```text
SuperSecure
```

## 八、利用過程

重新執行 binary 並輸入還原出的密碼：

```bash
./bypassme.bin
```

輸入：

```text
SuperSecure
```

程式成功通過驗證並輸出 flag。

## 九、利用結果

成功取得 flag：

```text
picoCTF{d3bugg3r_p0w3r_is_4w3s0m3_30b6c610}
```

## 十、完整操作摘要

```bash
ssh ctf-player@foggy-cliff.picoctf.net -p 61945
lldb ./bypassme.bin
```

```lldb
b decode_password
run
frame variable enc
memory read --format x --size 1 --count 11 &enc
disassemble --frame
```

解碼後得到：

```text
SuperSecure
```

再輸入該密碼取得 flag。

## 十一、成因分析

本題並非傳統意義上的漏洞利用，而是典型的逆向工程與動態分析題。其安全性依賴於：

1. 將正確密碼隱藏於 binary 內部
2. 以簡單 XOR 編碼避免直接由字串檢視得出
3. 假設使用者不會追蹤 `decode_password()` 的實作細節

但由於 binary 含完整 debug info 且未 strip，實際上大幅降低了分析難度。

## 十二、防禦建議

若在真實環境中要避免類似問題，應注意：

### 12.1 移除符號與除錯資訊

正式釋出的驗證程式不應保留完整 debug symbols。

### 12.2 避免將密碼硬編碼於用戶端 binary

任何靜態內嵌於程式中的秘密值，最終都可被分析還原。

### 12.3 避免使用可逆的簡單編碼

單純 XOR、位移或字元替換都只能延緩分析，無法真正提供安全性。

## 十三、結論

本題的解題關鍵在於善用 LLDB 直接追進 `decode_password()`，觀察 encoded bytes 與 XOR 解碼流程，還原出正確密碼 `SuperSecure`。題目表面上看似是認證繞過，實際上是標準的 debugger-assisted reverse engineering 題型，也非常適合作為練習動態分析與資料流還原的案例。

## 使用工具

- SSH
- strings
- LLDB
- x86-64 assembly analysis
