## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Forensics
- **Difficulty:** Hard
- **Author:** Bryan
- **Date:** 2026-04-12

## 一、基本資訊

- **題目名稱：** m00nwalk2
- **題目類型：** Forensics / Steganography / SSTV
- **平台：** picoCTF 2019
- **目標：** 從多個 WAV 音檔中找出 `message.wav` 的正確 passphrase，進一步解出隱藏內容並取得 flag

## 二、題目概述

本題提供四個音檔：`message.wav`、`clue1.wav`、`clue2.wav`、`clue3.wav`。表面上看起來像是單純的音訊分析題，但實際上此題結合了兩層隱寫概念：第一層是利用 SSTV 將 clue 音檔轉換為圖片，以取得提示資訊；第二層則是使用取得的 passphrase，透過 `steghide` 從 `message.wav` 中解出真正的隱藏資料。

因此，本題的核心並不是直接對 `message.wav` 進行暴力猜解，而是先透過 clue 音檔找出正確密碼，再對主音檔進行解鎖。

## 三、分析目標

本次分析的主要目標如下：

1. 確認 `message.wav` 是否包含隱藏資料
2. 分析 `clue1.wav`、`clue2.wav`、`clue3.wav` 的用途
3. 找出可用於解鎖 `message.wav` 的 passphrase
4. 使用 `steghide` 解出隱藏檔案
5. 取得 flag 並整理整體解題流程

## 四、初步分析

首先對 `message.wav` 使用 `steghide info` 進行確認：

```bash
steghide info message.wav
```

執行後程式會要求輸入 passphrase。這代表：

- `message.wav` 內確實藏有資料
- 但必須提供正確密碼，才能將其解出
- 單純對 `message.wav` 進行暴力測試並不是最佳方向

因此可以推斷，題目附帶提供的三個 clue 音檔，極可能就是為了協助取得 passphrase。

## 五、弱點判定 / 題目關鍵機制

### 5.1 題目本質

本題並非傳統程式漏洞利用，而是典型的多階段隱寫分析題。其核心技術包含：

- SSTV（Slow Scan Television）
- 音訊中隱藏提示資訊
- 使用 passphrase 的 steghide 載體抽取

### 5.2 關鍵概念

題目可拆成兩層：

1. **第一層：** clue 音檔透過 SSTV 解碼後可得到提示圖片
2. **第二層：** 使用提示圖片中的密碼，解開 `message.wav` 中的隱藏資料

### 5.3 風險說明（從鑑識角度）

本題展現了鑑識分析中常見的情境：資料不一定直接存在於檔案明文中，而可能必須先經過特定編碼或轉換方式才能顯現。若分析者只對檔案執行 `strings`、`cat` 或一般文字搜尋，往往只能得到片段雜訊，而無法取得真正關鍵資訊。

## 六、攻擊 / 解題思路

本題的正確流程如下：

1. 先確認 `message.wav` 為被密碼保護的 steghide 載體
2. 再針對 `clue1.wav`、`clue2.wav`、`clue3.wav` 進行分析
3. 使用 SSTV 將 clue 音檔轉成圖片
4. 從 clue1 對應的圖片中取得 passphrase
5. 使用該 passphrase 對 `message.wav` 執行 `steghide extract`
6. 讀取輸出的文字檔，取得最終 flag

## 七、利用過程

### 7.1 確認 message.wav 需要 passphrase

```bash
steghide info message.wav
```

此步驟的目的在於確認 `message.wav` 並非普通音檔，而是 steghide 載體。

### 7.2 分析 clue 音檔

在解題過程中，可先使用 `strings`、spectrogram 等方法做輔助檢查，但這些方法大多只會得到片段雜訊或局部線索，例如：

- `clue2.wav` 可抓到類似 `BKEYC*=;3?&` 的字串
- `clue1.wav`、`clue3.wav` 的明文線索不明顯

這代表僅靠 `strings` 並不足以完整還原 clue 的意義。

### 7.3 使用 SSTV 解 clue 音檔

將 `clue1.wav` 以 SSTV 工具解碼後，可得到包含 passphrase 的圖片。關鍵資訊為：

```text
hidden_stegosaurus
```

此字串即為後續解鎖 `message.wav` 所需的 passphrase。

### 7.4 使用 steghide 解出隱藏資料

取得 passphrase 後，對 `message.wav` 執行：

```bash
steghide extract -sf message.wav -p hidden_stegosaurus
```

成功後會輸出一個文字檔。

### 7.5 讀取隱藏檔案內容

```bash
cat steganopayload*.txt
```

即可讀出最終 flag。

## 八、利用結果

成功從 `message.wav` 中解出隱藏文字檔，並取得 flag：

```text
picoCTF{the_answer_lies_hidden_in_plain_sight}
```

## 九、完整 exploit / 解題指令

```bash
steghide info message.wav
steghide extract -sf message.wav -p hidden_stegosaurus
ls -la
cat steganopayload*.txt
```

## 十、成因分析

本題的難點主要來自於題目設計上的多階段資訊隱藏，而非單一工具即可直接解出。造成分析困難的原因如下：

1. **主檔案不直接暴露資料**
   - `message.wav` 雖然藏有資料，但若沒有 passphrase，無法直接解出。

2. **提示檔案不是明文文字**
   - clue 音檔中的資訊不是以一般字串方式存在，而是需透過 SSTV 轉成圖片後才會顯現。

3. **輔助工具容易產生干擾**
   - `strings` 或頻譜分析可提供少量線索，但不足以直接推得完整答案。

4. **多工具串接分析**
   - 分析者需要具備對 steghide、SSTV、音訊檔案與頻譜概念的基本理解，才能正確收斂到解題方向。

## 十一、防禦建議

雖然本題屬於 CTF 題目，但若從實務角度延伸，可得到以下鑑識與偵測啟示：

### 11.1 不要只依賴字串掃描

對音訊、圖片、文件等檔案進行安全分析時，`strings` 僅能作為輔助工具，不能視為唯一依據。

### 11.2 應考慮訊號與編碼層面的分析

當資料可能透過 SSTV、spectrogram、DTMF、FSK 等方式隱藏時，應搭配專門工具檢查，而不是只看檔案表層內容。

### 11.3 多階段載體需分層處理

若檔案本身同時具備「提示載體」與「隱藏資料載體」特性，分析流程應拆成多個階段，逐步驗證每個中介資訊的用途。

### 11.4 留意 passphrase 型載體

像 `steghide` 這類工具若使用了 passphrase，通常代表該檔案必須搭配額外線索解題或解密，因此應優先尋找密碼來源，而非盲目爆破。

## 十二、結論

本題的核心並不是直接破解 `message.wav`，而是先理解 clue 音檔的用途。透過 SSTV 解碼 clue 圖片後，可取得關鍵 passphrase `hidden_stegosaurus`，再利用 `steghide` 從 `message.wav` 中解出隱藏文字檔，最終取得 flag `picoCTF{the_answer_lies_hidden_in_plain_sight}`。

此題展示了數位鑑識中常見的多層隱寫概念：資料可能先被藏在訊號中，再用該訊號衍生出的資訊解開另一個載體。若分析者僅使用單一工具或只看檔案表面，很容易錯失真正關鍵。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題目主軸 | 多階段音訊隱寫分析 |
| 第一層技術 | SSTV 解碼 clue 音檔 |
| 第二層技術 | steghide 抽取隱藏資料 |
| 關鍵密碼 | `hidden_stegosaurus` |
| 最終成果 | 成功解出 `message.wav` 中的隱藏文字並取得 flag |

## 使用工具

- `steghide`
- SSTV 解碼工具（如 MMSSTV / QSSTV）
- `strings`
- `sox`（輔助 spectrogram 分析）
- Linux shell / WSL
