## Challenge Metadata

- **Platform:** picoCTF

- **Category:** Reverse Engineering

- **Difficulty:** Medium

- **Author:** Bryan

- **Date:** 2026-03-20

## 一、基本資訊

- **題目名稱：** ASCII FTW

- **題目類型：** Reverse Engineering

- **平台：** picoCTF

- **目標：** 透過反組譯分析程式如何以 hex ASCII 值組合 flag，並還原正確旗標內容

## 二、題目概述

本題提供一個 ELF 64-bit 執行檔，題目描述指出：程式會使用 hex ASCII values 來建構 flag，要求分析者透過反組譯找出最終的 flag 字串。

與直接將 flag 明文放在字串區不同，本題將每個字元拆成對應的十六進位 ASCII 值，並在 main 函式中逐一寫入記憶體。分析者需要觀察這些指令，將十六進位數值轉換回可讀字元，最終拼回完整 flag。

本題核心不在動態 exploitation，而是：

- 利用靜態分析理解程式行為
- 辨識 mov BYTE PTR ..., 0x?? 這類逐字元寫入模式
- 將 hex 值還原為 ASCII 字元
- 重建完整 flag

## 三、分析目標

本次分析的主要目標如下：

1. 分析程式基本檔案型態與執行架構
2. 找出 main 函式中與 flag 建構有關的指令
3. 辨識每個 byte 對應的 ASCII 字元
4. 還原完整 flag
5. 理解此類題型常見的逆向分析模式

## 四、靜態分析

首先使用 file 指令確認檔案屬性：

```bash
file asciiftw
```

可得知目標檔案為：

ELF 64-bit LSB PIE executable

x86-64

dynamically linked

not stripped

這表示：

- 檔案為 Linux ELF 執行檔
- 架構為 x86-64
- 未被 strip，通常保留符號資訊，方便直接找到 main
- 適合使用 objdump 或 gdb 進行反組譯分析
- 接著利用：
- objdump -d asciiftw -M intel
- 並定位 main 函式：
- 0000000000001169 <main>:
- 在 main 內部可觀察到大量連續指令如下：
- mov BYTE PTR [rbp-0x30],0x70
- mov BYTE PTR [rbp-0x2f],0x69
- mov BYTE PTR [rbp-0x2e],0x63
- mov BYTE PTR [rbp-0x2d],0x6f
- mov BYTE PTR [rbp-0x2c],0x43
- mov BYTE PTR [rbp-0x2b],0x54
- mov BYTE PTR [rbp-0x2a],0x46
- mov BYTE PTR [rbp-0x29],0x7b
- ...
- mov BYTE PTR [rbp-0x12],0x7d
- 這類指令的意義是：
- 將單一 byte 寫入 stack 上的某個位址
- 每個 0x?? 都是對應字元的 ASCII 十六進位表示
- 多條連續指令合起來就是一整串字串
- 例如：
- 0x70 → p
- 0x69 → i
- 0x63 → c
- 0x6f → o
- 0x43 → C
- 0x54 → T
- 0x46 → F
- 0x7b → {
- 將全部 byte 依序轉換後，可還原出完整 flag。

## 五、弱點判定

### 5.1 分析重點描述

本題並非典型漏洞利用題，而是逆向工程題。其關鍵點在於：

程式未直接以可見明文方式儲存 flag，而是透過逐 byte 寫入的方式動態組裝字串。分析者若只依賴 strings，可能無法直接取得完整結果，因此需要進一步觀察反組譯內容。

### 5.2 題型特徵

Hex ASCII Reconstruction

Static Reverse Engineering

String Construction Analysis

Disassembly-based Flag Recovery

### 5.3 風險說明

從防禦視角來看，這類寫法的目的通常是：

避免 flag 被簡單的字串搜尋直接找出

增加初學者在靜態分析上的門檻

但由於程式仍必須在執行時組出完整字串，因此只要能觀察其反組譯邏輯，就仍可還原最終內容。

## 六、攻擊思路

程式原始流程：

在 main 中逐一將 ASCII 對應值寫入記憶體
→ 組成完整字串
→ 供後續輸出或處理

分析目標：

辨識這些 byte 寫入操作
→ 將每個 hex 值轉為 ASCII
→ 還原 flag

攻擊核心在於：

找出關鍵函式 main

辨識連續 mov BYTE PTR 指令

依序轉換並拼接每個字元

確認最後的結尾字元 0x7d，也就是 }

## 七、利用過程

### 7.1 確認檔案型態

先列出檔案並確認其格式：

```bash
ls
file asciiftw
```

確認為未 strip 的 ELF 64-bit 執行檔。

### 7.2 找出 main 函式

使用 objdump 反組譯並搜尋 main：

```bash
objdump -d asciiftw -M intel | grep "<main>"
```

得到：

0000000000001169 <main>:

### 7.3 觀察字串建構指令

接著輸出 main 周圍內容，發現多條逐 byte 寫入指令：

```
1184: c6 45 d0 70    mov BYTE PTR [rbp-0x30],0x70
1188: c6 45 d1 69    mov BYTE PTR [rbp-0x2f],0x69
118c: c6 45 d2 63    mov BYTE PTR [rbp-0x2e],0x63
1190: c6 45 d3 6f    mov BYTE PTR [rbp-0x2d],0x6f
```

...
```
11fc: c6 45 ee 7d    mov BYTE PTR [rbp-0x12],0x7d
```

### 7.4 還原 ASCII 字元

將觀察到的 byte 依序轉換：

```
0x70 → p
```

```
0x69 → i
```

```
0x63 → c
```

```
0x6f → o
```

```
0x43 → C
```

```
0x54 → T
```

```
0x46 → F
```

```
0x7b → {
```

```
0x41 → A
```

```
0x53 → S
```

```
0x43 → C
```

```
0x49 → I
```

```
0x49 → I
```

```
0x5f → _
```

```
0x49 → I
```

```
0x53 → S
```

```
0x5f → _
```

```
0x45 → E
```

```
0x41 → A
```

```
0x53 → S
```

```
0x59 → Y
```

```
0x5f → _
```

```
0x37 → 7
```

```
0x42 → B
```

```
0x43 → C
```

```
0x44 → D
```

```
0x39 → 9
```

```
0x37 → 7
```

```
0x31 → 1
```

```
0x44 → D
```

```
0x7d → }
```

### 7.5 取得 flag

成功還原出的完整 flag 為：

```
picoCTF{ASCII_IS_EASY_7BCD971D}
```

## 八、利用結果

成功透過反組譯分析 main 函式中的逐 byte 寫入邏輯，將 hex ASCII 值逐一轉換為可讀字元，最終還原完整 flag。

## 九、完整 exploit 概念

反組譯 main
→ 找出 mov BYTE PTR ..., 0x??
→ 將 hex 值轉為 ASCII
→ 拼接完整字串
→ 取得 flag

## 十、成因分析

本題設計的核心思路如下：

1. 避免明文暴露

程式未直接將 flag 作為完整字串常數儲存，而是拆成多個 byte，在執行時重建，降低 strings 直接取出的可能性。

2. 提升靜態分析門檻

透過將字串建構邏輯藏於 main 的組語指令中，要求分析者必須理解：

反組譯內容

ASCII 對照

記憶體寫入模式

3. 引導學習基礎逆向技巧

本題是 Reverse Engineering 入門常見題型，重點不在複雜保護，而在培養：

ELF 觀察能力

```bash
objdump / gdb 使用能力
```

指令與字元之間的映射理解

## 十一、防禦建議

若從保護敏感字串的角度來看，可考慮以下方式：

### 11.1 避免將敏感字串直接硬編碼

即使拆成 byte，只要最終仍在本地端程式內重建，仍可被逆向還原。

### 11.2 使用更高層級的保護機制

例如：

加密後於執行時解密

搭配反除錯

混淆控制流程

減少靜態可讀性

### 11.3 避免將真正敏感資訊交由客戶端保存

若資料本身高度敏感，最佳作法通常不是單純混淆，而是避免將完整敏感資訊放在可被分析的用戶端程式中。

## 十二、結論

本題展示了一個典型的 hex ASCII reconstruction reverse engineering 題型。

雖然程式沒有直接將 flag 以明文顯示，但由於其在 main 中以多條 mov BYTE PTR ..., 0x?? 指令逐字元建構字串，只要分析反組譯輸出並將各個十六進位數值轉回 ASCII，即可順利重建 flag。

此案例說明，即使表面上隱藏了字串，只要程式在本地端必須完成重建，就仍可透過靜態分析將其還原。對逆向初學者而言，這是非常典型且重要的基本功。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題型 | Reverse Engineering |
| 核心方法 | 反組譯 main 後還原 ASCII |
| 關鍵指令 | mov BYTE PTR ..., 0x?? |
| 利用條件 | 可觀察程式反組譯內容 |
| 利用方式 | 將 hex 值逐一轉換為字元 |
| 攻擊效果 | 還原被拆分組裝的 flag |
| 本題成果 | 成功取得 picoCTF{ASCII_IS_EASY_7BCD971D} |

## 使用工具

- Linux shell
- file
- objdump
- gdb
- ASCII / hex 對照分析
