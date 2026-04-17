## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Digital Forensics
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-18

## 一、基本資訊

- **題目名稱：** DISKO 3
- **題目類型：** Digital Forensics
- **平台：** picoCTF
- **目標：** 分析 disk image，找出隱藏的 flag

## 二、題目概述

本題提供一個 disk image 檔案 disko-3.dd.gz，需先解壓後進行分析。題目提示：

- This time, it's not as plain as you think it is!

表示 flag 不會以明文形式直接存在，而是透過某種方式進行隱藏。

經分析可發現，disk image 採用 FAT32 檔案系統，並包含大量系統 log 檔案。flag 並非以一般 .txt 檔案形式出現，而是經過壓縮後混入 log 目錄中。

## 三、分析目標

本次分析的主要目標如下：

- 確認 disk image 的檔案系統結構
- 列出所有檔案並進行篩選
- 找出可疑檔案
- 抽取並還原檔案內容
- 取得 flag

## 四、靜態分析

首先解壓縮檔案：

- gunzip disko-3.dd.gz

確認檔案類型：

- file disko-3.dd

結果顯示：

- FAT32 filesystem
- 無需額外 offset 即可直接分析

接著列出檔案系統內容：

- fls -r disko-3.dd

在輸出中發現關鍵檔案：

- r/r 522628: flag.gz

## 五、弱點判定

### 5.1 弱點描述

flag 並未直接以明文或一般檔案形式存在，而是被壓縮成 .gz 檔案，並隱藏於 log 目錄中。

### 5.2 弱點類型

- Hidden File
- Compression Obfuscation
- Poor Data Protection

### 5.3 風險說明

壓縮並不具備安全性，任何人只要取得檔案，即可透過解壓還原內容。

此外，將敏感資料混入 log 檔案中，會增加分析難度，但無法防止資料外洩。

## 六、攻擊思路

分析流程如下：

- 使用 fls 列出所有檔案
- 搜尋可疑檔名（如 flag、secret）
- 發現 flag.gz
- 使用 icat 根據 inode 抽出檔案
- 解壓縮取得 flag

## 七、利用過程

- fls -r disko-3.dd
- 發現：flag.gz (inode: 522628)
- icat disko-3.dd 522628 > flag.gz
- gunzip flag.gz
- cat flag

## 八、利用結果

成功取得 flag：

- picoCTF{...}

## 九、完整 exploit 操作

- gunzip disko-3.dd.gz
- fls -r disko-3.dd
- icat disko-3.dd 522628 > flag.gz
- gunzip flag.gz
- cat flag

## 十、成因分析

本題的隱藏機制主要來自於資料處理方式，而非程式漏洞。

問題點如下：

- 使用壓縮取代保護
- 檔案混淆（將 flag 放入 log 目錄中增加辨識難度）
- 缺乏加密機制（資料未加密，任何人皆可還原）

## 十一、防禦建議

11.1 使用加密

- 應使用加密技術（如 AES），而非單純壓縮。

11.2 控制存取權限

- 限制敏感檔案的讀取權限。

11.3 分離敏感資料

- 避免將重要資料混入 log 或一般檔案中。

## 十二、結論

本題透過 disk image 提供一個模擬真實系統環境，要求分析者使用數位鑑識工具進行分析。

經過檔案系統掃描後可發現：

- flag 被壓縮為 flag.gz
- 存放於 log 目錄中
- 必須透過 inode 抽取與解壓縮還原

本題核心在於：

- filesystem analysis
- Sleuth Kit 工具使用
- 資料隱藏與還原

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 技術 | Digital Forensics |
| 工具 | fls / icat / gunzip |
| 隱藏方式 | gzip 壓縮 + 目錄混淆 |
| 攻擊方式 | 抽取 inode + 解壓縮 |
| 本題成果 | 成功取得 flag |

## 使用工具

- fls
- icat
- gunzip
- file
