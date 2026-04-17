## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Binary Exploitation
- **Difficulty:** Medium / Hard
- **Author:** Bryan
- **Date:** 2026-03-18

## 一、基本資訊

- **題目名稱：** Picker IV
- **題目類型：** Binary Exploitation
- **平台：** picoCTF
- **目標：** 控制 function pointer 並執行 win() 取得 flag

## 二、題目概述

本題提供一個選單式程式，允許使用者：

- 配置記憶體
- 輸入資料
- 呼叫特定功能

程式中存在一個關鍵機制：

```
void check_win() { ((void (*)())*(int*)x)(); }
```

該函式會讀取指標 x、將其轉換為函式指標並執行該位址的函式。

若攻擊者可以控制 x 的值，就可讓程式跳轉至任意位置。

本題核心在於：

- 利用記憶體漏洞（heap / overflow）
- 覆蓋 function pointer
- 劫持控制流程（Control Flow Hijacking）
- 呼叫 win() 取得 flag

## 三、分析目標

- 分析程式記憶體配置
- 找出可控制的指標變數 x
- 確認 win() 函式位置
- 設計 payload 覆蓋 x
- 成功呼叫 win()

## 四、靜態分析

關鍵程式碼：

```
void check_win() {
    ((void (*)())*(int*)x)();
}
```

x 存放一個位址，該位址被當成函式執行；程式執行流程可被 x 控制。

## 五、弱點判定

### 5.1 弱點描述

程式允許使用者透過輸入修改記憶體內容、覆蓋指標；如果 x 存在於 heap 或可被 overflow 覆蓋，攻擊者可覆蓋 x 為 win() 位址。

### 5.2 弱點類型

- Function Pointer Hijacking
- Control Flow Hijacking
- Heap / Memory Corruption

### 5.3 風險說明

原始流程：

- check_win() → 呼叫 x 指向的函式

若 x 被攻擊者控制：

- check_win() → 呼叫 win() → 任意程式執行

## 六、攻擊思路

攻擊流程：

1. 找到可寫入記憶體位置
2. 覆蓋 x
3. 設定為 win() 位址
4. 呼叫 check_win()
5. 執行 win()，取得 flag

## 七、利用過程

1. 取得 win() 位址（如 nm / objdump）
2. 找出 x 位置（分析程式/heap layout）
3. 建立 payload：padding + address_of_win
4. 覆蓋 function pointer x
5. 呼叫 check_win()；執行 win()
6. 取得 flag

## 八、利用結果

成功透過 function pointer hijack：

- 覆蓋指標 x
- 控制程式執行流程
- 呼叫 win()
- 取得 flag

## 九、完整 exploit 概念

- overwrite(x) = address_of_win
- → call check_win()
- → execute win()

或：

- payload → control pointer → hijack execution

## 十、成因分析

1. 指標 x 未受保護
2. function pointer 直接執行，無驗證
3. 缺乏記憶體保護

## 十一、防禦建議

- 驗證 function pointer：if (x != allowed_function) exit(1);
- 避免直接執行 user-controlled pointer
- 使用安全設計：設定 function pointer 為唯讀，不允許外部修改
- 啟用保護機制：ASLR、RELRO、NX、Stack Canary

## 十二、結論

本題展示了一個典型的 Control Flow Hijacking 漏洞。攻擊者透過覆蓋 function pointer，程式執行流程從原本邏輯轉向 win()，取得 flag。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 弱點名稱 | Function Pointer Hijacking |
| 利用條件 | 可修改指標 x |
| 利用方式 | 覆蓋 x 為 win() 位址 |
| 攻擊效果 | 控制流程轉向 win() |
| 本題成果 | 取得 flag |

## 使用工具

- Linux shell
- nm/objdump
- heap/stack 分析
