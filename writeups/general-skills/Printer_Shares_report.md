## Challenge Metadata

- **Platform:** picoCTF
- **Category:** General Skills
- **Difficulty:** Easy
- **Author:** Bryan
- **Date:** 2026-3-27

## 一、基本資訊

**題目名稱：** Printer Shares  
**題目類型：** General Skills  
**平台：** picoCTF 2026  
**目標：** 從網路印表機分享中找回被誤送出的重要檔案

## 二、題目概述

本題敘述指出有人不小心把重要檔案送到了 network printer，希望玩家能從 print server 取回檔案。題目先提供一個 port 並提示可用 nc -vz 測試，但真正的重點不是純 socket 互動，而是辨識該服務實際上是 SMB share。

本題的核心在於：

- 正確辨識遠端服務不是單純文字協定
- 使用 smbclient 列出可用 share
- 進入匿名可讀的 shares 目錄
- 抓取 flag.txt 內容

## 三、分析目標

本次分析的主要目標如下：

- 確認遠端 port 可連線
- 判斷服務類型
- 使用 smbclient 列出 share
- 進入可匿名存取的 share
- 下載並讀取 flag.txt

## 四、環境觀察

一開始使用：

nc -vz mysterious-sea.picoctf.net <port>

只得到 port 開啟的資訊，未直接拿到內容。進一步以 smbclient 測試後，成功列出遠端 share：

- shares
- IPC$

這表示題目真正的服務類型是 SMB，而非單純的 raw nc 協定。

## 五、核心分析：SMB Share 枚舉

### 5.1 服務辨識

使用：

smbclient -L //mysterious-sea.picoctf.net -p 61880 -N

可得知遠端提供匿名可讀的 shares。

### 5.2 進入 share

接著連入：

smbclient //mysterious-sea.picoctf.net/shares -p 61880 -N

執行 ls 後可見：

- dummy.txt
- flag.txt

### 5.3 關鍵觀察

在 smbclient 互動介面中不能使用本機 shell 的 cat，需改用 get 下載檔案後再於本機查看。

## 六、攻擊思路

本題利用鏈如下：

- 確認目標 port 開啟
- → 判斷該服務實際為 SMB share
- → 用 smbclient 列出分享名稱
- → 進入 shares
- → 使用 ls 確認有 flag.txt
- → 使用 get flag.txt 下載
- → 回到本機 shell 以 cat 讀取內容

## 七、利用過程

### 7.1 測試 port

先用 nc -vz 確認目標埠存在服務。

### 7.2 列出 share

執行：

smbclient -L //mysterious-sea.picoctf.net -p 61880 -N

列出：

- shares
- IPC$

### 7.3 進入可讀 share

執行：

smbclient //mysterious-sea.picoctf.net/shares -p 61880 -N

### 7.4 枚舉檔案

在 smbclient 提示符中執行：

ls

可見遠端包含：

- dummy.txt
- flag.txt

### 7.5 下載檔案

在 smbclient 中執行：

get flag.txt

接著退出：

exit

再於本機 shell 中讀取：

cat flag.txt

## 八、利用結果

本次對話紀錄已完整確認利用路徑與檔案取得方式，但最終 flag 文字未於紀錄中保存，因此此處僅保留利用流程。

## 九、完整 exploit 指令

```sh
smbclient -L //mysterious-sea.picoctf.net -p 61880 -N
smbclient //mysterious-sea.picoctf.net/shares -p 61880 -N
```

進入後：

```sh
ls
get flag.txt
exit
```

回到本機：

```sh
cat flag.txt
```

## 十、成因分析

### 10.1 題目訓練目標

本題主要訓練：

- 不要被 nc 提示誤導
- 能夠辨識常見檔案分享協定
- 理解 SMB share 枚舉流程
- 使用 smbclient 互動與取檔

### 10.2 典型錯誤

- 誤以為只要 nc 連進去就會吐出 flag
- 在 smbclient 裡直接使用 cat
- 未先辨識實際服務類型

## 十一、防禦建議

### 11.1 不應允許匿名讀取敏感分享

若 share 可匿名列目錄並直接讀取機敏檔案，則風險極高。

### 11.2 應最小化分享內容

印表機或共享目錄不應存放包含旗標或敏感資料的明文檔案。

### 11.3 應限制 SMB 權限與可見性

分享名稱、列目錄與讀取權限都應嚴格控管。

## 使用工具

- nc
- smbclient
- SMB share enumeration
