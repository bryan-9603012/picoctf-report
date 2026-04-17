## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Binary Exploitation
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-18

## 一、基本資訊

- **題目名稱：** Picker III
- **題目類型：** Binary Exploitation
- **平台：** picoCTF
- **目標：** 利用 heap overflow 覆蓋關鍵資料並取得 flag

## 二、題目概述

本題提供一個互動式程式，會在 heap 上配置多個記憶體區塊，並允許使用者輸入資料。

程式主要流程：

- 配置 heap 記憶體（malloc）
- 將使用者輸入寫入 buffer
- 使用該資料執行後續操作

程式在讀取輸入時未限制長度，導致攻擊者可以輸入超過 buffer 大小的資料，進而覆蓋相鄰的 heap 區塊。

本題核心在於：

- 利用 Heap Buffer Overflow
- 覆蓋關鍵變數或指標
- 控制程式行為並取得 flag

## 三、分析目標

- 分析 heap 記憶體配置方式
- 找出輸入處理中的安全漏洞
- 確認 heap chunk 間的關係
- 設計 exploit payload
- 成功覆蓋目標資料並取得 flag

## 四、靜態分析

程式核心行為如下：

- malloc buffer A
- malloc buffer B
- 將使用者輸入寫入 A
- 使用 B 執行某些操作

關鍵問題：輸入寫入 A 時未限制長度，A 與 B 在 heap 上相鄰，導致 Input → Overflow A → 覆蓋 B。

## 五、弱點判定

### 5.1 弱點描述

程式使用不安全的輸入方式，例如：

- scanf("%s", buffer);
- gets(buffer);

若 buffer 大小有限（如 char *buf = malloc(32)），當輸入超過 32 bytes 時，會發生 Heap Buffer Overflow。

### 5.2 弱點類型

- Heap Buffer Overflow
- Memory Corruption
- Unsafe Input Handling

### 5.3 風險說明

Heap 記憶體可能排列如下：

- [ chunk A (user input) ]
- [ chunk B (target data) ]

當 overflow 發生：

- A 被填滿
- B 被覆蓋

若 chunk B 儲存指令、pointer 或 function reference，攻擊者可控制程式行為。

## 六、攻擊思路

原始流程：

- buffer A → 存使用者資料
- buffer B → 被程式使用

攻擊目標：

- overflow A → 覆蓋 B → 控制 B 的內容

核心概念：

- 找出 A 與 B 的距離（offset）
- 設計 payload 填滿 A
- 覆蓋 B 的內容
- 讓程式使用被修改的資料

## 七、利用過程

1. 觀察 heap 配置（A address, B address）
2. 計算距離：B - A = offset
3. 建立 payload："A" * offset + malicious_data
4. 覆蓋目標 chunk
5. 觸發程式使用 B（如 system(B)）
6. 取得 flag

## 八、利用結果

成功透過 heap overflow 覆蓋相鄰 chunk，控制程式使用資料，執行攻擊者指定指令，取得 flag。

## 九、完整 exploit 概念

- "A" * offset + "/bin/sh"

或：

- padding → overwrite heap chunk → control execution

## 十、成因分析

1. 未限制輸入長度
2. heap 記憶體相鄰配置
3. 使用可被覆蓋的資料

## 十一、防禦建議

- 限制輸入長度：scanf("%31s", buffer) 或 fgets()
- 避免直接使用 system(user_input)
- 加入 heap 保護：heap integrity check, modern allocator protection
- 啟用安全機制：ASLR, NX, Heap protection

## 十二、結論

本題展示了一個典型的 Heap Buffer Overflow 漏洞。未限制輸入長度導致 overflow，覆蓋相鄰 memory chunk 後更改程式行為，最終取得 flag。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 弱點名稱 | Heap Buffer Overflow |
| 利用條件 | 未限制輸入長度 |
| 利用方式 | 覆蓋相鄰 chunk |
| 攻擊效果 | 控制程式行為 |
| 本題成果 | 取得 flag |

## 使用工具

- Linux shell
- 解析 heap alloc
- 基本測試
