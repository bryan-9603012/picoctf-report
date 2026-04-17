## Challenge Metadata

- **Platform:** picoCTF
- **Category:** General Skills
- **Difficulty:** Easy
- **Author:** Bryan
- **Date:** 2026-3-27

## 一、基本資訊

**題目名稱：** MY GIT  
**題目類型：** General Skills  
**平台：** picoCTF 2026  
**目標：** 依照自訂 Git 規則推送指定檔案，讓伺服器更新 flag

## 二、題目概述

本題提供一個自建 Git 伺服器，題目要求玩家使用指定 SSH repository 進行 clone，並在 README 中尋找取得 flag 的方法。

README 顯示：

If you want the flag, make sure to push the flag!  
Only flag.txt pushed by ```root:root@picoctf``` will be updated with the flag.

本題的核心在於：

- 正確使用 Git over SSH clone 題目 repo
- 閱讀 README 了解伺服器規則
- 設定符合條件的 commit 身分資訊
- 建立並 push flag.txt
- 讓遠端伺服器依規則更新檔案內容

## 三、分析目標

本次分析的主要目標如下：

- 成功 clone 遠端 repository
- 讀取 README.md 了解伺服器規則
- 設定符合題意的作者身分
- push flag.txt 至遠端
- 驗證遠端是否將 flag.txt 更新為真實旗標

## 四、環境觀察

使用題目提供的 SSH URL 與密碼 clone repository 後，可成功取得 challenge repo。

README.md 顯示核心規則：

Only flag.txt pushed by ```root:root@picoctf``` will be updated with the flag.

這表示伺服器端很可能會檢查 push 內容或 commit author，只有符合規則的 flag.txt 才會被自動改寫成真正 flag。

## 五、弱點／設計分析

### 5.1 題目設計重點

此題不是典型漏洞利用，而是 Git metadata 與 server-side automation 的邏輯題。

### 5.2 關鍵利用點

玩家需控制與 Git 身分相關的欄位，例如：

- user.name
- user.email
- commit author

使其符合題目要求的 root / root@picoctf 條件。

### 5.3 技術意義

本題測試玩家是否理解：

- clone / push 基本流程
- README 中題意提示的重要性
- Git 作者資訊與伺服器端規則檢查的關聯

## 六、攻擊思路

本題利用鏈如下：

- 以 SSH clone 題目 repo
- → 閱讀 README.md
- → 設定 Git author 為 root / root@picoctf
- → 建立或修改 flag.txt
- → commit 並 push 至遠端
- → 由伺服器端邏輯將 flag.txt 更新為真正 flag
- → pull 或重新讀取 flag.txt 取得結果

## 七、利用過程

### 7.1 Clone repository

依照題目提供的 git clone 指令與密碼登入，成功取得本地 challenge repo。

### 7.2 閱讀 README

執行：

cat README.md

確認規則為只有由 root:root@picoctf 推送的 flag.txt 會被更新。

### 7.3 設定作者身分

可設定：

git config user.name root  
git config user.email root@picoctf

必要時也可在 commit 時額外以 --author 指定。

### 7.4 建立與推送 flag.txt

建立或修改 flag.txt，接著：

git add flag.txt  
git commit -m "add flag"  
git push origin <branch>

### 7.5 驗證結果

push 成功後，再次同步遠端內容並讀取 flag.txt，以確認伺服器端是否已更新成真實 flag。

## 八、利用結果

本次對話紀錄已確認解題路線與操作邏輯，但最終 flag 文字未於紀錄中保存，因此此處僅保留利用流程。

## 九、完整 exploit 指令

```sh
git config user.name root
git config user.email root@picoctf
echo test > flag.txt
git add flag.txt
git commit -m "add flag"
git push origin main
git pull
cat flag.txt
```

若主分支為 master，則改為 push origin master。

## 十、成因分析

### 10.1 過度信任 Git metadata

若伺服器端僅依賴 commit author 或類似字串判斷權限，則可被使用者自行偽造。

### 10.2 將安全規則外包給可控欄位

Git name / email 為使用者可控資料，不可作為高信任判斷依據。

### 10.3 題目訓練目標

本題主要訓練：

- Git SSH clone 與 push
- README-based reasoning
- Git metadata 操作
- server-side rule inference

## 十一、防禦建議

### 11.1 不應信任 commit author 作為身分驗證依據

真正的身分驗證應依賴經驗證的 SSH key、access control 或簽章機制，而非 name / email。

### 11.2 重要伺服器邏輯應綁定可信任認證來源

例如：

- authenticated account
- verified identity
- signed commit

## 使用工具

- git
- ssh
- README analysis
- Git author metadata
