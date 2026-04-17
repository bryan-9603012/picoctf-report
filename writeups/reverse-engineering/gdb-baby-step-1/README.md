## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-17

## 一、基本資訊

- **題目名稱：** GDB baby step 1
- **題目類型：** Reverse Engineering
- **平台：** picoCTF
- **目標：** 找出 main 函式結束時 eax 暫存器的值

## 二、題目概述

本題提供一個 ELF binary，要求分析 main 函式執行完畢後 eax 暫存器中的值，並以十進位形式提交 flag。

題目提示需對 binary 進行反組譯（disassemble），顯示考察：

- GDB 基本操作
- x86-64 暫存器理解
- Reverse Engineering 基礎分析能力

## 三、分析目標

- 確認程式入口點與執行流程
- 找出 main 函式位置
- 分析 main 中對 eax 的操作
- 將結果轉換為十進位
- 取得正確 flag

## 四、靜態分析

### 4.1 檔案類型確認

```
file debugger0_a
```

結果：

- ELF 64-bit executable
- x86-64 架構
- 未包含 debug symbols（strip）

### 4.2 Entry Point 分析

```
info files
```

得到：

- Entry point: 0x1040

### 4.3 _start 分析

```
disas 0x1040
```

關鍵片段：

- 0x1061: lea rdi, [rip+0xc1]   # 0x1129 <main>

可得： main = 0x1129

## 五、弱點判定

### 5.1 題目本質

本題並非傳統漏洞利用，而是：

- Reverse Engineering 分析題
- 重點在於理解程式執行流程

### 5.2 關鍵技術點

- stripped binary（無符號）
- _start → __libc_start_main → main
- eax 作為 return value

## 六、攻擊思路（分析流程）

程式執行流程：

- _start → __libc_start_main → main → return → eax

目標：找出 main 中最後寫入 eax 的值

## 七、利用過程

1. 定位 main：disas 0x1040（找到 0x1061 對應 main 0x1129）
2. 反組譯 main：disas 0x1129
3. 觀察指令：0x1138: mov eax, 0x86342; 0x113e: ret
4. 解析 eax：eax = 0x86342
5. 轉換為十進位：549698

## 八、利用結果

成功取得：

- picoCTF{549698}

## 九、完整解題流程（指令）

- gdb debugger0_a
- info files
- disas 0x1040  # 找到 main = 0x1129
- disas 0x1129

## 十、成因分析

本題設計重點：

- binary 被 strip，無法直接使用 b main
- 必須透過 _start 分析找到 main
- 需理解 x86-64 呼叫慣例（rdi 傳遞參數）

## 十一、防禦建議

> 教學性質：supplementary

- 保留 debug symbols（開發階段），有助除錯與分析
- 混淆與保護：symbol stripping、obfuscation、anti-debugging

## 十二、結論

本題透過簡單 binary 訓練：

- ELF entry point
- 程式啟動流程
- register 與 return value

最終透過反組譯 main，直接取得 eax = 0x86342，轉換十進位得 flag。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| eax | function return value |
| main | 程式主函式 |
| _start | 程式入口點 |
| rdi | 第一個參數（x86-64 calling convention） |
| strip | 移除符號資訊 |

## 使用工具

- GDB
- objdump
- Linux CLI
