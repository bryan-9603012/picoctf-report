## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Forensics
- **Difficulty:** Medium
- **Author:** DarkRaicg492
- **Date:** 2026-03-18

## 一、基本資訊

- **題目名稱：** DISKO 2
- **題目類型：** Digital Forensics
- **平台：** picoCTF
- **目標：** 分析 disk image，找出正確的 Linux partition，並從中擷取 flag

## 二、題目概述

本題提供一個 .dd 磁碟映像檔，要求分析其中的資料並找出 flag。

題目特別提示：

- The right one is Linux

這表示 disk image 中包含多個 partition，其中只有 Linux filesystem 是正確的分析目標，其餘為干擾資訊。

在初步分析中可發現：

- Disk image 包含多個 partition
- 存在不同 filesystem（ext4、FAT16）
- raw data 中包含大量偽造 flag

因此本題核心在於：

- 正確辨識 partition
- 選擇正確 filesystem
- 避免被假 flag 誤導

## 三、分析目標

本次分析的主要目標如下：

- 分析 disk image 結構
- 辨識 partition 與 filesystem 類型
- 判斷正確的分析目標（Linux partition）
- 過濾干擾資訊（fake flags）
- 擷取真實 flag

## 四、靜態分析

### 4.1 Disk Image 檢查

首先對 disk image 進行解壓與檢查：

- gunzip disko-2.dd.gz

### 4.2 Partition 分析

使用 parted 檢查 partition：

- sudo parted disko-2.dd print

結果顯示：

- Partition 1 26.2MB ext4
- Partition 2 33.6MB fat16

### 4.3 Filesystem 判定

根據 filesystem 類型：

- ext4 -> Linux
- fat16 -> Windows / Legacy

結合題目提示 The right one is Linux，可確定：

- Partition 1 (ext4) 為正確分析目標

## 五、弱點判定

### 5.1 弱點描述

本題並非傳統漏洞利用，而是設計為 Forensics 誤導型挑戰：

- 在 raw disk 中放置大量假 flag
- 使用多個 partition 混淆分析方向
- 利用 filesystem 差異作為關鍵提示

### 5.2 題目設計重點

- Data Obfuscation（資料混淆）
- Misleading Artifacts（誤導證據）
- Partition-based Filtering（分區篩選）

### 5.3 風險說明

若分析者直接對整個 disk image 執行：

- strings disko-2.dd | grep pico

將會得到大量錯誤結果，導致：

- 無法辨識正確 flag
- 分析方向錯誤
- 浪費時間

## 六、攻擊思路（分析策略）

- Disk Image
- Partition Analysis
- Filesystem Identification
- Focus on Linux (ext4)
- Extract Relevant Data

關鍵點：

- 不分析整個 disk
- 僅分析 Linux partition
- 過濾非目標 filesystem

## 七、利用過程

1. 建立 loop device：sudo losetup -Pf disko-2.dd
2. 掛載 Linux partition：sudo mount /dev/loop0p1 /mnt/disko
3. 掃描 Linux filesystem：sudo strings /dev/loop0p1 | grep pico

## 八、利用結果

成功取得 flag：

- picoCTF{4_P4Rt_1t_i5_a93c3ba0}

## 九、完整操作流程

- gunzip disko-2.dd.gz
- sudo parted disko-2.dd print
- sudo losetup -Pf disko-2.dd
- sudo mount /dev/loop0p1 /mnt/disko
- sudo strings /dev/loop0p1 | grep pico

## 十、成因分析

本題的核心在於分析方法錯誤會導致錯誤結果。

問題點：

- 直接分析 raw disk
- 未辨識 filesystem 類型
- 未根據提示選擇正確 partition

## 十一、防禦建議

在真實數位鑑識情境中，應採取以下策略：

### 11.1 分層分析

- Disk → Partition → Filesystem → File

### 11.2 避免直接使用 strings

- 先定位 filesystem
- 再進行資料擷取

### 11.3 使用專業工具

- mmls（partition analysis）
- fls（file listing）
- icat（file recovery）

## 十二、結論

本題透過多個 partition 與大量假 flag 來干擾分析者，並利用 filesystem 類型作為關鍵提示。

正確解法需先辨識 Linux filesystem（ext4），再針對該 partition 進行分析，最終成功取得 flag。

此題重點不在漏洞利用，而在於正確的數位鑑識流程與分析策略。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題型 | Digital Forensics |
| 核心技巧 | Partition Analysis |
| 關鍵提示 | Linux filesystem |
| 常見錯誤 | 掃描整個 disk |
| 正確方法 | 分區分析 |
| 本題成果 | 成功取得 flag |

## 使用工具

- parted
- losetup
- mount
- strings
- The Sleuth Kit（fls / icat）
