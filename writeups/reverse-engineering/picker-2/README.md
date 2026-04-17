## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Binary Exploitation
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-18

## 一、基本資訊

- **題目名稱：** Picker II
- **題目類型：** Binary Exploitation
- **平台：** picoCTF
- **目標：** 利用記憶體漏洞控制程式行為並取得 flag

## 二、題目概述

本題提供一個選單式程式，允許使用者輸入資料並進行處理。程式會將使用者輸入存入固定大小的 buffer，並在後續流程中使用該資料。

然而，程式在處理輸入時未對長度進行限制，導致攻擊者可以輸入超過 buffer 容量的資料，進而覆蓋記憶體中的其他變數。

本題的核心在於：

- 利用 Stack Buffer Overflow
- 覆蓋關鍵資料
- 控制程式執行流程
- 最終取得 flag

## 三、分析目標

- 分析程式的記憶體配置（stack）
- 找出輸入處理中的安全漏洞
- 確認可被覆蓋的變數位置
- 設計 exploit payload
- 成功控制程式執行流程並取得 flag

## 四、靜態分析

程式主要行為如下：

1. 接收使用者輸入
2. 將資料存入固定大小 buffer
3. 執行後續操作

關鍵問題在於：

- 使用不安全函式（如 gets / strcpy / scanf("%s")）
- 未檢查輸入長度

導致：

User Input → 超過 buffer → 覆蓋 stack 資料

## 五、弱點判定

### 5.1 弱點描述

程式中存在以下問題：

```
char buffer[SIZE];
gets(buffer);  // 無長度限制
```

由於 buffer 大小有限，但輸入未受限制，當輸入長度超過 buffer 時，會造成 Stack Buffer Overflow 並覆蓋後方記憶體。

### 5.2 弱點類型

- Stack Buffer Overflow
- Memory Corruption
- Unsafe Input Handling

### 5.3 風險說明

在 stack 中，記憶體排列可能如下：

- [ buffer ]
- [ saved rbp ]
- [ return address ]

當 overflow 發生時，可覆蓋：

- 區域變數
- saved rbp
- return address

若攻擊者能控制 return address，則可：

- 控制程式跳轉位置
- 執行任意程式碼或函式

## 六、攻擊思路

原始流程：

- 正常輸入 → 程式正常執行

攻擊目標：

- Overflow → 覆蓋關鍵資料 → 控制流程

攻擊核心：

- 找出 buffer 大小
- 計算 offset
- 覆蓋目標位置（如 return address 或變數）
- 導向 win() 函式

## 七、利用過程

1. 找出 offset（例如用 "A" * N）
2. 建立 payload：padding + target address
3. 通過 overflow 覆蓋關鍵資料
4. 觸發程式 return，跳轉到指定位置（如 win()）
5. 取得 flag

## 八、利用結果

成功透過 Stack Buffer Overflow 覆蓋關鍵記憶體，控制程式執行流程，呼叫 win()，取得 flag。

## 九、完整 exploit 概念

- "A" * offset + address_of_win

或：

- padding → overwrite return address → jump to win()

## 十、成因分析

1. 使用不安全函式（gets / strcpy / scanf("%s")）
2. 缺乏邊界檢查
3. 記憶體保護不足

## 十一、防禦建議

- 使用安全函式：fgets(buffer, sizeof(buffer), stdin)
- 限制輸入長度：scanf("%9s", buffer)
- 啟用保護機制：Stack Canary、ASLR、NX
- 編譯器安全選項：-fstack-protector、-D_FORTIFY_SOURCE=2

## 十二、結論

本題展示了一個典型的 Stack Buffer Overflow 漏洞。程式未對輸入長度進行限制，攻擊者可覆蓋 stack 重要資訊控制流程，最終執行 win() 取得 flag。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 弱點名稱 | Stack Buffer Overflow |
| 利用條件 | 輸入長度未限制 |
| 利用方式 | 覆蓋 return address |
| 攻擊效果 | 控制程式流程 |
| 本題成果 | 呼叫 win() 取得 flag |

## 使用工具

- Linux shell
- 基本輸入測試
- （可選）GDB
