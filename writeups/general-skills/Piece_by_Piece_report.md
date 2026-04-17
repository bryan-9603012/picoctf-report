## Challenge Metadata

- **Platform:** picoCTF
- **Category:** General Skills
- **Difficulty:** Easy
- **Author:** Bryan
- **Date:** 2026-3-27

## 一、基本資訊

**題目名稱：** Piece by Piece  
**題目類型：** General Skills  
**平台：** picoCTF 2026  
**目標：** 合併分割檔並解壓縮取得 flag

## 二、題目概述

本題要求玩家透過 SSH 登入遠端主機，於家目錄中找到多個檔案分段，將它們重新組合後再解壓縮，以取得最後的 flag。

題目提供了明確提示：

- flag 被 split 成多個 parts
- 這些 parts 組合後是一個 zip 檔
- zip 檔具有密碼保護
- 解壓後需查看文字檔內容

本題的核心在於：

- 辨識分割檔命名規律
- 使用 Linux 指令正確合併檔案
- 針對密碼保護 zip 進行解壓
- 讀取解壓後文字檔中的 flag

## 三、分析目標

本次分析的主要目標如下：

- 確認家目錄中的檔案結構
- 閱讀 instructions.txt 提示
- 正確合併各 part 檔案
- 使用給定密碼解壓 zip
- 成功取得 flag

## 四、環境觀察

登入後執行 ls，可見：

- instructions.txt
- part_aa
- part_ab
- part_ac
- part_ad
- part_ae

查看 instructions.txt 可得題目關鍵提示：

- The flag is split into multiple parts as a zipped file.
- Use Linux commands to combine the parts into one file.
- The zip file is password protected. Use this "supersecret" password to extract the zip file.
- After unzipping, check the extracted text file for the flag.

這表示解題方式已相當明確。

## 五、核心分析：檔案分割與重組

### 5.1 題目行為

題目將 zip 檔分割成多個 parts 放在使用者家目錄中。

### 5.2 還原方式

最直接的作法是依照正確順序將它們串接回單一 zip 檔：

cat part_aa part_ab part_ac part_ad part_ae > flag.zip

### 5.3 技術意義

這反映了 Linux 在處理檔案切割與重組時的基本技巧：

- cat 可將多個 binary parts 按順序串接
- 只要順序正確，即可還原原始壓縮檔

## 六、攻擊思路

本題利用鏈如下：

- SSH 登入遠端主機
- → 觀察家目錄內容
- → 讀取 instructions.txt
- → 使用 cat 依序合併 part_aa 至 part_ae
- → 形成 flag.zip
- → 以提供的密碼 supersecret 解壓縮
- → 查看解壓後文字檔取得 flag

## 七、利用過程

### 7.1 列出檔案

執行：

ls

確認目標分段檔存在。

### 7.2 閱讀提示檔

執行：

cat instructions.txt

取得關鍵提示，包括 zip 格式與解壓密碼 supersecret。

### 7.3 合併分段檔

執行：

cat part_aa part_ab part_ac part_ad part_ae > flag.zip

### 7.4 解壓縮

執行：

unzip flag.zip

系統要求輸入密碼時，輸入：

supersecret

### 7.5 讀取旗標

解壓完成後，以 cat 查看解出的文字檔，取得 flag。

## 八、利用結果

取得的 flag：

picoCTF{z1p_and_spl1t_f1l3s_4r3_fun_8fa833a5}

## 九、完整 exploit 指令

```sh
cat part_aa part_ab part_ac part_ad part_ae > flag.zip
unzip flag.zip
```

解壓密碼：

supersecret

## 十、成因分析

本題並非漏洞利用，而是 Linux 檔案處理基礎練習。

### 10.1 檔案重組觀念

檔案可被切成多個部分存放，只要順序正確，便能重新組回原始內容。

### 10.2 壓縮與密碼保護觀念

玩家需辨識題目使用的是 zip，並正確輸入提供的解壓密碼。

### 10.3 題目訓練目標

- SSH 基本操作
- ls 與 cat 使用
- 檔案合併
- zip 解壓
- 讀取文字檔內容

## 十一、防禦建議

本題屬教學型練習，但延伸到實務上可反映：

### 11.1 檔案切割不等於保護

將檔案拆成多段並不能提供真正安全性，只要取得全部 parts 即可還原。

### 11.2 提示中的敏感資訊管理

若密碼與檔案放在同一位置，安全性極低，真實環境不應如此設計。

## 使用工具

- ssh
- ls
- cat
- unzip
