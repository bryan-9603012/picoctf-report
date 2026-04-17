## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Binary Exploitation
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-3-13

## 一、基本資訊

**題目名稱：** hash-only-2  
**題目類型：** Binary Exploitation  
**平台：** picoCTF 2025  
**目標：** 取得 /root/flag.txt 的明文內容

## 二、題目概述

本題提供一個具備較高權限的程式 flaghasher，其功能是讀取 flag 檔案後輸出雜湊值，而非直接顯示明文。
與前一題不同的是，本題登入後使用者會先進入 restricted shell (rbash)，因此除了分析 flaghasher 本身的行為外，還需要先處理 shell 限制問題。

本題的核心並不在於還原 MD5，而是在於：

- 繞過 restricted shell
- 利用高權限程式呼叫 /bin/bash -c ... 時的環境變數機制
- 透過 BASH_ENV 劫持非互動式 bash 的啟動流程
- 在真正執行 md5sum 前先輸出 flag 明文

## 三、分析目標

本次分析的主要目標如下：

- 確認登入後的 shell 限制
- 確認 flaghasher 的執行方式
- 找出可利用的 shell 啟動機制
- 設計 exploit 並取得 flag
- 說明弱點成因與防禦方法

## 四、環境觀察

登入後首先觀察環境，可發現目前使用的是 rbash。

**觀察結果**

`SHELL=/bin/rbash`

直接輸入含有 / 的完整路徑命令會被限制

例如：

無法直接執行 /challenge/flaghasher

無法自由使用某些重導向與路徑操作

這說明題目故意增加了一層限制，避免使用者直接用完整路徑碰觸目標程式。

## 五、第一層弱點：Restricted Shell Escape

### 5.1 弱點描述

雖然題目一開始將使用者限制在 rbash 中，但若系統仍允許直接執行一般 bash，則使用者可透過：

bash

跳出 restricted shell，取得較完整的 shell 功能。

### 5.2 弱點成因

rbash 只是受限制的 shell 介面，不應被視為完整的安全邊界。
若系統沒有額外限制可執行程式，使用者仍可能直接啟動新的 shell，進而逃離原本限制環境。

### 5.3 安全意義

這表示：

- rbash 並不等於真正隔離
- 若沒有額外配合檔案權限、白名單機制、程式限制等措施，使用者可直接脫離受限環境

## 六、第二層弱點：BASH_ENV 劫持

### 6.1 題目程式行為

在成功進入一般 bash 後，執行 flaghasher 可觀察到程式會顯示：

Computing the MD5 hash of /root/flag.txt....

這說明它會透過某種方式去呼叫 md5sum 計算 /root/flag.txt 的雜湊值。

本題的實際利用點在於：
flaghasher 內部會透過 /bin/bash -c ... 執行命令。

### 6.2 BASH_ENV 的作用

在 Bash 中，若啟動的是 non-interactive shell，則 bash 會在執行命令前讀取 BASH_ENV 指定的檔案內容。

也就是說，若高權限程式使用：

/bin/bash -c 'md5sum /root/flag.txt'

而攻擊者可以控制環境變數：

BASH_ENV=/tmp/exploit.sh

那麼在 bash -c 真正執行 md5sum 前，會先執行 /tmp/exploit.sh 裡面的內容。

### 6.3 弱點本質

本題的核心弱點在於：

- 高權限程式依賴 /bin/bash -c ... 執行外部命令
- 執行前未清理危險環境變數
- Bash 會信任 BASH_ENV
- 攻擊者可藉此插入惡意指令

## 七、攻擊思路

本題利用鏈如下：

- 進入 rbash
- → 執行 bash 跳出 restricted shell
- → 建立惡意腳本 exploit.sh
- → 設定 BASH_ENV 指向該腳本
- → 執行高權限 flaghasher
- → flaghasher 內部呼叫 /bin/bash -c ...
- → bash 先載入 BASH_ENV 指定腳本
- → 惡意腳本先執行 cat /root/flag.txt
- → 成功取得 flag

## 八、利用過程

### 8.1 跳出 restricted shell

bash

成功後，可取得一般 bash 環境。

### 8.2 建立惡意腳本

建立一個內容為直接輸出 flag 的腳本：

```sh
printf 'cat /root/flag.txt\n' > /tmp/exploit.sh
```

此腳本內容等同於：

cat /root/flag.txt

### 8.3 設定 BASH_ENV

export BASH_ENV=/tmp/exploit.sh

這樣當任何 non-interactive bash 被啟動時，就會先讀取 /tmp/exploit.sh。

### 8.4 執行目標程式

flaghasher

程式執行後，雖然原本目的是計算 /root/flag.txt 的 MD5，但在真正進行 hash 計算之前，bash 已先載入 BASH_ENV，因此先執行了：

cat /root/flag.txt

最終成功輸出 flag。

## 九、利用結果

取得的 flag 

## 十、完整 exploit 指令

```sh
bash
printf 'cat /root/flag.txt\n' > /tmp/exploit.sh
export BASH_ENV=/tmp/exploit.sh
flaghasher
```

## 十一、成因分析

本題的弱點可分為兩部分。

### 11.1 restricted shell 設計不足

系統雖將使用者放入 rbash，但仍允許直接執行一般 bash，導致限制可被輕易繞過。

### 11.2 高權限程式信任 shell 啟動機制

flaghasher 內部透過 /bin/bash -c ... 執行命令，卻未清理 BASH_ENV 等環境變數，使攻擊者能控制 bash 啟動時執行的內容。

### 11.3 未遵守最小信任原則

高權限程式不應信任使用者可控環境，尤其是在透過 shell 執行命令時，應預設環境變數皆可能被濫用。

## 十二、防禦建議

### 12.1 不要將 rbash 當成完整安全邊界

restricted shell 只能作為輔助限制，不能單獨作為主要防護措施。

### 12.2 避免使用 /bin/bash -c

若程式只是要執行固定行為，應直接呼叫對應 API 或系統函式，而不是透過 shell。

### 12.3 清理危險環境變數

在高權限程式中，應主動清除如以下環境變數：

BASH_ENV

ENV

## 使用工具

- bash
- environment variables
- restricted shell bypass
