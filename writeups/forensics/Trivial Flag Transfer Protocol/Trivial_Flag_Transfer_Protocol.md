## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Forensics
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-04-23

## 一、基本資訊

- **題目名稱：** Trivial Flag Transfer Protocol
- **題目類型：** Forensics
- **平台：** picoCTF
- **目標：** 分析 `tftp.pcapng` 中的 TFTP 傳輸內容，找出被隱藏的 flag

## 二、題目概述

本題提供一個封包擷取檔 `tftp.pcapng`，題目提示為「Figure out how they moved the flag.」。

從題目名稱可推測與 **TFTP（Trivial File Transfer Protocol）** 有關，因此核心方向是分析封包中透過 TFTP 傳輸的檔案，再從傳輸出的物件中找出與 flag 相關的線索。

實際分析後可發現，封包中傳輸了多個 BMP 圖片檔與提示內容，最終需要從 `picture3.bmp` 中以 `steghide` 解出隱藏的 `flag.txt`。

## 三、分析目標

本次分析的主要目標如下：

1. 確認封包中使用的協定類型
2. 找出 TFTP 傳輸的檔案名稱
3. 匯出傳輸物件並分析其中的提示內容
4. 還原隱寫圖片中的嵌入資料
5. 取得 flag

## 四、靜態分析

### 4.1 確認封包格式

先使用 `file` 檢查題目提供的檔案：

```bash
file tftp.pcapng
```

輸出結果顯示其為：

```text
pcapng capture file - version 1.0
```

表示該檔案是標準的封包擷取檔，可使用 `tshark` 或 Wireshark 進一步分析。

### 4.2 確認與 TFTP 相關的欄位

使用：

```bash
tshark -G fields | grep -i tftp
```

可確認目前 `tshark` 支援的 TFTP 欄位，例如：

- `tftp.opcode`
- `tftp.source_file`
- `tftp.destination_file`
- `tftp.data`
- `tftp.block`

因此後續可直接用這些欄位過濾與觀察 TFTP 傳輸內容。

### 4.3 找出 TFTP 傳輸檔案

使用下列指令觀察封包中傳輸的檔名：

```bash
tshark -r tftp.pcapng -Y tftp -T fields -e frame.number -e tftp.opcode -e tftp.source_file -e tftp.destination_file
```

分析結果可得知封包中出現多個圖片檔案，例如：

- `picture1.bmp`
- `picture2.bmp`
- `picture3.bmp`

其中 `picture2.bmp` 會反覆出現，是因為 TFTP 傳輸過程中會有 **DATA / ACK** 封包反覆交錯，屬正常現象。

## 五、解題過程

### 5.1 匯出 TFTP 傳輸物件

在 Wireshark 中開啟 `tftp.pcapng`，透過：

```text
File → Export Objects → TFTP
```

即可將封包中經 TFTP 傳輸的檔案匯出。

匯出後可得到多個檔案，其中包含：

- `picture1.bmp`
- `picture2.bmp`
- `picture3.bmp`
- 提示文字內容

### 5.2 初步檢查 picture2.bmp

一開始先檢查 `picture2.bmp`：

```bash
exiftool picture2.bmp
strings picture2.bmp | grep pico
zsteg picture2.bmp
steghide info picture2.bmp
```

結果顯示：

- `exiftool` 僅確認其為正常 BMP 檔
- `strings` 沒有直接出現 flag
- `zsteg` 雖然有一些雜訊文字，但沒有直接有效線索
- `steghide` 雖提示可能有嵌入資料，但以後續正確線索驗證後，真正藏有 flag 的並不是 `picture2.bmp`

### 5.3 從提示內容找出密碼線索

從匯出的提示文字中可得到一串經過 ROT13 編碼的字串：

```text
VHFRQGURCEBTENZNAQUVQVGJVGU-QHRQVYVTRAPR.PURPXBHGGURCUBGBF
```

將其進行 ROT13 解碼後得到：

```text
IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS
```

這句話的重點是：

- `I USED THE PROGRAM`：表示使用了某個隱寫工具
- `HID IT WITH-DUE DILIGENCE`：提示 passphrase 與 **DUEDILIGENCE** 有關
- `CHECK OUT THE PHOTOS`：提示要檢查圖片檔

### 5.4 確認真正藏有資料的圖片

接著對 `picture3.bmp` 使用 `steghide info`：

```bash
steghide info picture3.bmp
```

輸入正確 passphrase 後，顯示：

```text
embedded file "flag.txt":
  size: 40.0 Byte
  encrypted: rijndael-128, cbc
  compressed: yes
```

這表示 `picture3.bmp` 才是實際藏有 `flag.txt` 的圖片。

### 5.5 使用正確密碼取出 flag

最後使用正確 passphrase：

```bash
steghide extract -sf picture3.bmp -p DUEDILIGENCE
cat flag.txt
```

成功輸出：

```text
picoCTF{h1dd3n_1n_pLa1n_51GHt_18375919}
```

## 六、完整解答指令

```bash
# 1. 確認檔案格式
file tftp.pcapng

# 2. 查看 tshark 支援的 TFTP 欄位
tshark -G fields | grep -i tftp

# 3. 觀察 TFTP 傳輸檔名
tshark -r tftp.pcapng -Y tftp -T fields -e frame.number -e tftp.opcode -e tftp.source_file -e tftp.destination_file

# 4. 在 Wireshark 匯出 TFTP 物件
# File -> Export Objects -> TFTP

# 5. 檢查真正藏資料的圖片
steghide info picture3.bmp

# 6. 取出隱藏檔案
steghide extract -sf picture3.bmp -p DUEDILIGENCE

# 7. 讀取 flag
cat flag.txt
```

## 七、輸出結果

執行後成功取得 flag：

```text
picoCTF{h1dd3n_1n_pLa1n_51GHt_18375919}
```

## 八、成因分析

本題的核心概念在於：

1. **封包鑑識（Packet Forensics）：** 從封包擷取檔中辨識協定與傳輸內容
2. **TFTP 傳輸分析：** 透過檔名、區塊與物件匯出還原實際傳輸檔案
3. **ROT13 提示解碼：** 從提示字串中還原真正的密碼線索
4. **隱寫分析（Steganography）：** 使用 `steghide` 從圖片中提取隱藏檔案
5. **密碼格式判斷：** 題目提示為 `DUE DILIGENCE`，實際 passphrase 為無空格的大寫 `DUEDILIGENCE`

## 九、結論

本題雖然表面上只是分析 TFTP 傳輸，但實際上結合了：

- 封包分析
- 物件匯出
- 提示解碼
- 圖片隱寫

解題關鍵在於：

1. 先從 `tftp.pcapng` 確認是 TFTP 傳檔
2. 匯出封包中的圖片與提示內容
3. 從 ROT13 提示推得 passphrase 與圖片方向
4. 找到真正藏有資料的 `picture3.bmp`
5. 使用 `DUEDILIGENCE` 成功取出 `flag.txt`

此題很適合用來練習封包鑑識與多步驟線索串接的能力，特別是從協定分析一路走到 steganography 的完整流程。

## 十、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 封包格式 | `tftp.pcapng` 為 pcapng 封包擷取檔 |
| 主要協定 | TFTP |
| 傳輸檔案 | `picture1.bmp`、`picture2.bmp`、`picture3.bmp` |
| 關鍵提示 | `IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS` |
| 提示解碼方式 | ROT13 |
| 隱寫工具 | `steghide` |
| 正確 passphrase | `DUEDILIGENCE` |
| 最終 flag | `picoCTF{h1dd3n_1n_pLa1n_51GHt_18375919}` |

## 使用工具

- file
- tshark
- Wireshark
- exiftool
- strings
- zsteg
- steghide
