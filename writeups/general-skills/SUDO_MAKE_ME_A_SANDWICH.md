## Challenge Metadata

- **Platform:** picoCTF
- **Category:** General Skills
- **Difficulty:** Easy
- **Author:** Bryan
- **Date:** 2026-3-28

## 一、基本資訊

- **題目名稱：** SUDO MAKE ME A SANDWICH
- **題目類型：** General Skills
- **平台：** picoCTF 2026
- **目標：** 在具有限制的 Linux 帳號環境中讀取受保護的 `flag.txt`

## 二、題目概述

本題提供一組 SSH 連線資訊，使用者登入遠端主機後，可看到目錄中的 `flag.txt`，但直接使用一般權限讀取時會得到 `Permission denied`。本題的題名已明確提示核心概念與 `sudo` 有關，因此重點不在於繞過檔案系統本身，而在於確認目前帳號被允許透過 `sudo` 執行哪些特定程式，並進一步利用該程式讀取受保護檔案。

## 三、分析目標

本次分析的主要目標如下：

1. 確認目前帳號是否具備 `sudo` 權限
2. 列出可用的 `sudo` 白名單程式
3. 利用允許執行的程式讀取 `flag.txt`
4. 說明此類設定風險與防禦方式

## 四、環境觀察

登入遠端環境後，可先確認目錄內容：

```bash
ls
```

顯示存在：

```text
flag.txt
```

但直接讀取：

```bash
cat flag.txt
```

會得到：

```text
cat: flag.txt: Permission denied
```

這代表：

- 目前使用者可看見檔案名稱
- 但不具備直接讀取該檔案內容的權限

## 五、權限分析

### 5.1 錯誤方向排除

一開始若直接嘗試：

```bash
sudo cat flag.txt
```

系統會拒絕，顯示該使用者不能以 root 執行 `/usr/bin/cat flag.txt`。這表示本題不是「任意 sudo」，而是「僅允許特定程式的 sudo」。

### 5.2 列出 sudo 白名單

使用以下指令檢查：

```bash
sudo -l
```

觀察到允許項目為：

```text
(ALL) NOPASSWD: /bin/emacs
```

這表示：

- 目前帳號可用 `sudo` 執行 `/bin/emacs`
- 不需要輸入密碼
- 權限來源為 `sudoers` 白名單設定
- 雖然不能直接 `sudo cat`，但可透過 root 權限的文字編輯器讀取檔案

## 六、弱點判定

### 6.1 弱點描述

本題的本質是：

- 管理者將高權限程式 `emacs` 納入 `sudo` 白名單
- `emacs` 本身具備讀取任意使用者可存取檔案的能力
- 一旦以 root 權限執行，就等同提供了一個可間接讀取敏感檔案的介面

### 6.2 弱點類型

- Misconfigured sudoers
- Privileged Program Abuse
- Indirect File Read via Allowed Editor

### 6.3 風險說明

編輯器、分頁器、解譯器與 shell 類工具若被放入 sudo 白名單，通常都可被用來：

- 讀取敏感檔案
- 開啟 shell
- 進一步執行其他命令

因此，即便白名單中未包含 `cat`、`bash` 等直觀危險指令，只要允許的是功能過於完整的程式，仍可能造成權限繞過。

## 七、利用思路

本題可直接使用 root 權限啟動終端版 emacs：

```bash
sudo /bin/emacs -nw flag.txt
```

參數 `-nw` 的作用是：

- 在純終端機環境中啟動 emacs
- 不依賴 GUI 視窗
- 適合 SSH 遠端操作

當 `emacs` 以 root 權限開啟 `flag.txt` 時，即可直接檢視原本不可讀取的檔案內容。

## 八、利用過程

### 8.1 確認 sudo 權限

```bash
sudo -l
```

### 8.2 以 root 權限開啟檔案

```bash
sudo /bin/emacs -nw flag.txt
```

### 8.3 取得結果

成功後即可在 emacs 介面中讀取 `flag.txt` 內容。

## 九、利用結果

本次解題已確認可透過 `sudo /bin/emacs -nw flag.txt` 成功讀取受保護檔案。  
但本次對話紀錄中未保留最終 flag 字串，因此此處僅保留已驗證成功的利用方式與結果狀態。

## 十、成因分析

本題弱點產生的主要原因如下：

1. `sudoers` 白名單配置過寬
   - 將具備完整檔案操作能力的編輯器納入可提權執行範圍
2. 未限制編輯器可開啟的目標檔案
   - 一旦使用者可指定檔名，就可讀取任意 root 可讀檔案
3. 將互動式高功能工具視為安全白名單對象
   - 這類工具通常內建更多進階功能，實務上不適合直接授與高權限

## 十一、防禦建議

### 11.1 避免將編輯器納入 sudo 白名單

`vim`、`emacs`、`nano`、`less` 等互動式工具通常可被轉為讀檔或命令執行介面，不應任意開放。

### 11.2 使用最小權限原則

若僅需完成特定動作，應提供封裝好的固定用途程式，而非直接授權通用工具。

### 11.3 限制可執行命令與參數

若業務上確有需求，應以 wrapper 程式限制固定路徑與固定檔案，而不是允許使用者自由指定目標。

## 十二、結論

本題表面上是一般 Linux 權限題，實際上考的是 `sudoers` 白名單配置風險。當管理者允許使用者以 root 權限執行 `emacs` 時，雖然沒有直接授權 `cat` 或 shell，使用者仍可藉由編輯器功能讀取受保護檔案。這說明高功能互動式程式在提權情境下具有高度風險，若配置不當，往往足以形成完整的權限繞過。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 核心弱點 | `sudoers` 白名單配置不當 |
| 利用條件 | 可 `sudo` 執行 `/bin/emacs` |
| 利用方式 | 以 root 權限用 emacs 開啟 `flag.txt` |
| 攻擊效果 | 間接讀取原本不可讀取的敏感檔案 |
| 本題成果 | 成功取得 `flag.txt` 內容 |

## 使用工具

- SSH
- sudo
- emacs
- Linux shell
