## Challenge Metadata

- **Platform:** picoCTF
- **Category:** General Skills / Binary Interaction
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-22
## 一、基本資訊

- **題目名稱：** bytemancy 3
- **題目類型：** Binary Interaction / Symbol Address Resolution
- **平台：** picoCTF 2026
- **目標：** 根據遠端題目所點名的 procedure 名稱，從本地 binary spellbook 找出其位址，並以 raw 4-byte little-endian 形式回傳，連續答對三題取得 flag
## 二、題目概述

本題提供一個本地 ELF 執行檔 spellbook，並要求使用者透過遠端互動服務回覆某些函式的位址。題目大意如下：

I will name four procedures hidden inside spellbook.
Each round, send me their raw 4-byte addresses in little-endian form.
3 correct answers unlock the flag.

此題結合了以下觀念：

- ELF 符號表查詢
- little-endian 位元組序
- raw byte 輸入
- 遠端互動式題目自動化

## 三、分析目標

本次分析的主要目標如下：

1. 確認 spellbook 的檔案型態與符號資訊
2. 查找題目指定 procedure 的地址
3. 將地址轉換成 4-byte little-endian
4. 正確以 raw bytes 回傳給遠端服務
5. 解決互動式題目中常見的時序與輸入格式問題

## 四、靜態分析

首先檢查 binary 類型：

```bash
file spellbook
```

可確認其為 ELF 32-bit 可執行檔。

接著利用 nm 或 readelf 讀取符號表，例如：

```bash
nm -n spellbook
```

從輸出中可查得多個 procedure 名稱及其地址，例如：

ember_sigil
astral_spark
glyph_conflux
binding_word

此類符號位址存在於 binary 內，可透過符號表直接解析。

## 五、弱點／考點判定

### 5.1 題目本質

本題並非傳統漏洞利用題，而是針對以下能力的綜合測驗：

是否理解 ELF 符號與函式位址
是否理解 little-endian 打包方式
是否知道 raw bytes 與可見字串的差異
是否能處理互動式遠端服務的輸入時序
### 5.2 輸入要求

題目明確要求：

raw 4-byte addresses in little-endian form

因此若某函式位址為：

```
0x08049176
```

則正確送出形式應為：

```python
struct.pack("<I", 0x08049176)
```

亦即：

\x76\x91\x04\x08
## 六、錯誤分析與修正過程

### 6.1 錯誤一：過早以 pipeline 固定送值

初期若直接將某個地址透過：

```bash
python3 -c '...' | nc ...
```

送到遠端，容易發生題目尚未出現時就先送出 payload 的情況。
由於每次連線時伺服器所提問的 procedure 名稱可能不同，因此固定 payload 並不可行。

### 6.2 錯誤二：誤將一般文字中的 flag 視為成功

腳本初期若使用：

if "flag" in buffer.lower():

作為成功判斷，會被伺服器開場白中：

3 correct answers unlock the flag.

提早誤觸發，導致腳本在第一題就提前結束。

因此成功條件應改為更精準的：

if "picoCTF{" in buffer:

### 6.3 錯誤三：多送出換行導致後續位元組錯位

初版腳本使用：

```python
struct.pack("<I", addr) + b"\n"
```

但本題要求的是 raw 4-byte address，服務端很可能每輪剛好讀取 4 個位元組。
若多送一個 \n，第一題可能仍正確，但殘留的換行會污染下一輪輸入，導致第二題開始錯位並失敗。

因此最終修正為：

```python
struct.pack("<I", addr)
```

不附加換行。

## 七、利用思路

整體解法如下：

以 nm -n spellbook 建立 symbol name → address 對照表
連線到遠端服務
讀取當前題目要求的 procedure 名稱
於本地符號表中找到對應地址
使用 struct.pack("<I", addr) 轉為 little-endian raw bytes
送回遠端
連續完成三輪取得 flag
## 八、利用過程

### 8.1 讀取符號表

```bash
nm -n spellbook
```

### 8.2 Python 自動化解題腳本

```python
import re
import socket
import struct
import subprocess
```

```python
HOST = "green-hill.picoctf.net"
PORT = 50911
```

BINARY = "./spellbook"

```python
nm_out = subprocess.check_output(["nm", "-n", BINARY], text=True, errors="ignore")
symbols = {}
for line in nm_out.splitlines():
    parts = line.split()
    if len(parts) >= 3:
```

addr, typ, name = parts[0], parts[1], parts[2]
if typ in ("T", "t"):

symbols[name] = int(addr, 16)

```python
s = socket.create_connection((HOST, PORT))
```

s.settimeout(3)

```python
buffer = ""
```

try:

```python
    while True:
```

data = s.recv(4096)
if not data:

break

text = data.decode(errors="replace")
print(text, end="")
buffer += text

if "picoCTF{" in buffer:

break

if "Those aren't the right runes" in buffer or "Try again" in buffer:

break

m = re.search(r"\[\d+/\d+\] Send the 4-byte little-endian address for procedure '([^']+)'\.", buffer)
if m and "==>" in buffer:

name = m.group(1)
addr = symbols[name]
```python
            payload = struct.pack("<I", addr)
```

s.sendall(payload)
```python
            buffer = ""
```

finally:

s.close()
## 九、利用結果

成功根據題目要求，自動解析 procedure 名稱並送出正確 little-endian raw address，連續答對三題，取得 flag。

## 十、成因分析

本題的困難點並不在於傳統漏洞利用，而在於解題者是否能同時掌握：

binary 符號表查詢
little-endian 打包
raw bytes 傳輸
互動式遠端題目的輸入節奏

特別是最後一點，在實務上常是自動化腳本最容易失敗的地方。

## 十一、防禦建議／學習建議

對於類似題目，建議建立以下標準解題流程：

### 11.1 先確認題目要求的是字串還是 raw bytes

若題目明示 raw 4-byte，就不應額外附加換行或空白。

### 11.2 成功條件必須精準判斷

不要用模糊關鍵字，例如 flag，應使用具體旗標格式如 picoCTF{。

### 11.3 互動式題目應避免固定 pipe payload

若服務端會動態出題，就必須先收題、再即時計算答案。

### 11.4 讀懂大小端序

32-bit little-endian 的位址應以：

```python
struct.pack("<I", addr)
```

產生，避免手動拼接出錯。

## 十二、結論

bytemancy 3 是一題很典型的 binary interaction 題目。
它結合 ELF 符號表解析、little-endian 打包、raw byte 傳輸與互動式自動化處理。實際解題過程中，真正的障礙並不是找不到函式位址，而是如何正確處理 輸入格式、時序與殘留位元組。成功完成本題後，對後續 pwn / binary 題型的互動腳本撰寫會有明顯幫助。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題目核心 | procedure 名稱對應函式位址 |
| 資料來源 | spellbook 符號表 |
| 位址格式 | 4-byte little-endian |
| 正確打包方式 | struct.pack("<I", addr) |
| 常見錯誤 1 | 過早固定 pipe payload |
| 常見錯誤 2 | 用 flag 作為成功關鍵字 |
| 常見錯誤 3 | 多送 \n 導致下一輪錯位 |

## 使用工具

- netcat
- file
- nm
- Python 3
- socket
- struct
- 正則表達式
