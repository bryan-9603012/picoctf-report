## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-18

## 一、基本資訊

- **題目名稱：** GDB baby step 2
- **題目類型：** Reverse Engineering
- **平台：** picoCTF
- **目標：** 找出 main 函式結束時 eax 暫存器的值

## 二、題目概述

本題提供一個 ELF binary，需透過 GDB 進行反組譯與分析，找出程式在 main 函式結束時 eax 暫存器中的值。

與 GDB baby step 1 不同，本題加入了迴圈運算，需分析 assembly 程式碼並還原其邏輯，進一步計算最終結果。

本題核心在於：

- 理解 assembly 指令
- 分析 stack 上的變數
- 還原迴圈邏輯
- 計算最終 return value

## 三、分析目標

本次分析的主要目標如下：

- 找出程式 entry point
- 從 _start 定位 main
- 分析 main 內部邏輯
- 還原為高階語言
- 計算 eax 最終值

## 四、靜態分析

程式核心流程如下：

- _start → 呼叫 __libc_start_main
- → 將 main 位址傳入 rdi
- → 執行 main

透過 GDB：

```
gdb debugger0_b
info files
```

可得：

- Entry point: 0x401020

反組譯 _start：

```
disas 0x401020
```

關鍵指令：

- mov $0x401106,%rdi

代表：

- main = 0x401106

## 五、弱點判定

### 5.1 題目描述

本題並非漏洞利用題，而是 Reverse Engineering 分析題。

### 5.2 題目類型

- Reverse Engineering
- Assembly Analysis
- Control Flow Analysis

### 5.3 重點說明

需理解：

- eax 為 return value
- loop 運算流程
- stack 上的變數操作

## 六、分析思路

原始程式流程：

- main 初始化變數
- 進入迴圈進行加總
- 最終回傳計算結果

核心目標：

- 找出：eax = 最終結果

## 七、利用過程

### 7.1 反組譯 main

```
disas 0x401106
```

關鍵指令：

- movl $0x1e0da, -0x4(%rbp)
- movl $0x25f, -0xc(%rbp)
- movl $0x0, -0x8(%rbp)

### 7.2 邏輯分析

對應變數：

- A = 0x1e0da
- B = 0x25f
- i = 0

迴圈邏輯：

```
for (i = 0; i < B; i++) {
    A += i;
}
```

### 7.3 數值轉換

- A = 0x1e0da = 123098
- B = 0x25f   = 607

### 7.4 計算加總

- sum = 0 + 1 + 2 + ... + 606
- 公式：n(n-1)/2 = 607 × 606 / 2 = 183921

### 7.5 最終結果

- A = 123098 + 183921 = 307019

## 八、利用結果

成功取得 eax 值：

- 307019

flag：

- picoCTF{307019}

## 九、完整解題流程（指令）

- gdb debugger0_b
- info files
- disas 0x401020  # 找到 main
- disas 0x401106

## 十、成因分析

本題設計重點如下：

- 無 debug symbol
- 需從 _start 找 main
- 使用 stack 儲存變數
- 需理解 rbp offset
- 使用迴圈運算
- 需還原邏輯並計算

## 十一、防禦建議

（教學題）

可透過以下方式增加難度：

- code obfuscation
- control flow flattening
- anti-debug 技術

## 十二、結論

本題透過簡單的迴圈與變數操作，訓練分析者將 assembly 邏輯還原為高階語言並進行數學計算。

透過分析 main 函式可得 eax 最終值為 307019，成功取得 flag。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| eax | return value |
| rbp | stack frame |
| loop | 加總運算 |
| rdi | 傳入 main |
| _start | 程式入口 |

## 使用工具

- GDB
- Linux CLI
