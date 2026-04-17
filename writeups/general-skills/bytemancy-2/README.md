## Challenge Metadata

- **Platform:** picoCTF
- **Category:** General Skills
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-22
## 一、基本資訊

- **題目名稱：** bytemancy 2
- **題目類型：** General Skills / Raw Byte Handling
- **平台：** picoCTF 2026
- **目標：** 將指定的十六進位位元組以 raw bytes 形式送出，且需符合服務端的讀取方式
## 二、題目概述

本題由可見字元轉換進一步提升到 raw byte 輸入。題目提示為：

Send me the HEX BYTE 0xFF 3 times, side-by-side, no space.

此題的重點不再是輸出字元字串，而是送出三個真正的位元組 0xFF。
由於 0xFF 屬於不可見位元組，無法穩定以鍵盤手動輸入，因此必須透過腳本產生並送出。

## 三、分析目標

本次分析的主要目標如下：

1. 區分字串 "FF" 與 raw byte 0xFF 的差異
2. 確認題目要求的實際 payload
3. 理解服務端可能採用的輸入讀取方式
4. 正確送出三個 0xFF
5. 說明本題常見錯誤與修正過程

## 四、題目分析

題目要求：

HEX BYTE 0xFF 3 times

表示要送出的內容為：

```
b"\xff\xff\xff"
```

這不是字串：

FFFFFF

也不是可見字元，而是三個真正的原始位元組。

## 五、常見錯誤與修正

### 5.1 錯誤一：將 raw bytes 輸出到終端而非送給服務端

初期做法可能是：

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"\xff"*3)'
```

此時只會在本地終端上看到亂碼或替代符號，並不會自動將內容送給題目服務。

### 5.2 錯誤二：過早以 pipeline 送出資料

若直接使用：

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"\xff"*3)' | nc ...
```

可能會在題目正式進入讀取狀態前就送出資料，造成 payload 被提早消耗或忽略。

### 5.3 錯誤三：未補送換行

在實際互動中，本題服務端行為顯示其輸入介面採用接近「讀一整行」的方式，因此只送出三個 0xFF 不足以觸發提交。
最後修正為送出：

```
b"\xff\xff\xff\n"
```

其中：

\xff\xff\xff 是題目真正要求的內容
\n 是用來結束該次輸入並提交答案
## 六、利用過程

### 6.1 使用 Python 建立 socket 互動

```python
import socket
```

```python
HOST = "lonely-island.picoctf.net"
PORT = 52848
```

```python
s = socket.create_connection((HOST, PORT))
```

print(s.recv(4096).decode(errors="replace"))
s.sendall(b"\xff" * 3 + b"\n")
print(s.recv(4096).decode(errors="replace"))
s.close()
### 6.2 核心送出內容

```
b"\xff\xff\xff\n"
```

## 七、利用結果

成功通過 bytemancy 2，證明本題除了要求正確 raw bytes 外，也需配合服務端的輸入提交機制。

## 八、解題核心觀念

本題核心包括：

- 0xFF 是 raw byte，不是字串 "FF"
- 不可見位元組應以腳本送出
- 與遠端互動時，除了 payload 本身，也要考慮服務端的讀取模式
- 某些題目雖要求 raw bytes，但仍須補送 \n 作為行結束符

## 九、成因分析

本題設計重點在於讓解題者理解：

可見字元與原始位元組的差異
終端機顯示亂碼並不代表 payload 錯誤
真正的問題可能出在「互動時序」與「輸入提交方式」

這是許多 binary / pwn 類題目中常見的實戰問題。

## 十、防禦建議／學習建議

面對 raw bytes 題型，建議遵循以下流程：

先確認題目要求的是字串還是位元組
若是位元組，優先使用 Python sys.stdout.buffer.write() 或 socket sendall()
視情況判斷是否需補 \n
不要只看終端畫面顯示判斷 payload 是否錯誤
## 十一、結論

bytemancy 2 的核心不僅是送出 \xff\xff\xff，更在於正確理解 raw byte 輸入、互動式服務時序與行提交機制。
本題是從基礎編碼題過渡到更接近 binary interaction 題型的重要一步。

## 十二、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 指定位元組 | 0xFF |
| 重複次數 | 3 |
| 原始 payload | b"\xff\xff\xff" |
| 實際提交 payload | b"\xff\xff\xff\n" |
| 常見錯誤 | 誤送 "FFFFFF" 或過早 pipeline 傳送 |

## 使用工具

- netcat
- Python 3
- socket
- raw byte 輸入
