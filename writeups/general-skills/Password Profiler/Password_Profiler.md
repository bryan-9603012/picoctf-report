## Challenge Metadata

- **Platform:** picoCTF
- **Category:** General Skills
- **Difficulty:** Easy
- **Author:** Bryan
- **Date:** 2026-3-28

## 一、基本資訊

- **題目名稱：** Password Profiler
- **題目類型：** General Skills
- **平台：** picoCTF 2026
- **目標：** 根據目標個資建立自訂密碼字典，還原 SHA-1 對應的原始密碼並取得 flag

## 二、題目概述

本題提供三個檔案：

- `userinfo.txt`：目標人物個人資訊
- `hash.txt`：目標密碼對應的 SHA-1 雜湊值
- `check_password.py`：用於驗證候選密碼是否命中的比對腳本

根據檔案內容可知，題目不直接提供字典檔，而是要求解題者自行生成 `passwords.txt`。腳本中的註解也明確指出該字典檔應由 CUPP 產生，因此本題的核心並非破解強雜湊，而是結合 OSINT 與常見人類密碼習慣，對目標建立高命中的客製化字典。

## 三、分析目標

本次分析的主要目標如下：

1. 理解題目提供檔案之間的關係
2. 確認驗證腳本的密碼比對邏輯
3. 根據個資利用 CUPP 生成自訂字典
4. 以題目腳本驗證密碼並取得 flag
5. 說明此類攻擊在實務上的風險與防禦方式

## 四、題目檔案分析

### 4.1 驗證腳本

`check_password.py` 的關鍵流程如下：

```python
HASH_FILE = "hash.txt"
WORDLIST_FILE = "passwords.txt"

if hashlib.sha1(password.encode()).hexdigest() == target_hash:
    return password
```

可知：

- 題目使用的是純 SHA-1
- 不存在 salt
- 腳本會逐行讀取 `passwords.txt`
- 每個候選字串都會先做 SHA-1，再與 `hash.txt` 比對
- 一旦命中，就輸出 `picoCTF{密碼}`

### 4.2 目標 hash

`hash.txt` 內容為：

```text
968c2349040273dd57dc4be7e238c5ac200ceac5
```

### 4.3 個資內容

`userinfo.txt` 提供的資訊如下：

- First Name: Alice
- Surname: Johnson
- Nickname: AJ
- Birthdate: 15-07-1990
- Partner's Name: Bob
- Child's Name: Charlie

這些欄位非常適合用於建立高命中率字典，例如：

- 姓名與生日組合
- 暱稱與年份組合
- 家人姓名與符號組合
- 常見 leetspeak 變形

## 五、弱點判定

### 5.1 弱點描述

本題反映的是典型的弱密碼與個資關聯風險：

- 使用者常以自己的名字、暱稱、生日、家人名稱作為密碼基礎
- 攻擊者不必全面暴力破解，只需利用已知個資生成客製字典
- 若密碼選擇缺乏隨機性，則即使儲存為雜湊，仍可能被快速還原

### 5.2 弱點類型

- Weak Password Selection
- OSINT-based Password Guessing
- Dictionary Attack with Custom Wordlist

### 5.3 風險說明

此類情境在真實世界中很常出現在：

- 社交工程滲透測試
- 帳號口令審查
- 紅隊針對性存取嘗試
- 已洩漏 hash 的離線字典比對

一旦密碼與個資高度相關，攻擊者便可大幅縮小搜尋空間。

## 六、攻擊思路

題目已提示 `passwords.txt` 應由 CUPP 生成，因此解題流程可整理為：

1. 使用 `userinfo.txt` 中的個資作為輸入
2. 用 CUPP 產生目標專屬的密碼字典
3. 將生成的字典複製或改名為 `passwords.txt`
4. 執行 `check_password.py`
5. 由腳本自動找到對應 hash 的原始密碼

## 七、利用過程

### 7.1 下載並執行 CUPP

```bash
git clone https://github.com/Mebus/cupp.git
cd cupp
python3 cupp.py -i
```

### 7.2 依個資互動填寫

依序輸入：

- First Name: `Alice`
- Surname: `Johnson`
- Nickname: `AJ`
- Birthdate: `15071990`
- Partner's Name: `Bob`
- Child's Name: `Charlie`

其餘未知欄位可直接留空。  
為提高涵蓋率，可開啟：

- 特殊字元變形
- 數字追加
- leet mode

### 7.3 取得生成字典

CUPP 生成了：

```text
alice.txt
```

之後將其複製為題目要求的檔名：

```bash
cp cupp/cupp/alice.txt passwords.txt
```

### 7.4 執行驗證腳本

```bash
python3 check_password.py
```

## 八、利用結果

驗證腳本輸出：

```text
Password found: picoCTF{Aj_15901990}
```

因此本題最終 flag 為：

```text
picoCTF{Aj_15901990}
```

## 九、完整利用指令

```bash
git clone https://github.com/Mebus/cupp.git
cd cupp
python3 cupp.py -i

cd /path/to/challenge
cp cupp/cupp/alice.txt passwords.txt
python3 check_password.py
```

## 十、成因分析

本題能成功的核心原因如下：

1. 密碼設計與個資高度相關
   - `Aj_15901990` 由暱稱與數字模式組成，屬於高可預測性密碼
2. 使用無 salt 的 SHA-1
   - 雖然 SHA-1 仍需比對，但在字典已大幅縮小後，驗證成本很低
3. 題目腳本採逐行直接比對
   - 只要字典品質夠好，很快就能命中

## 十一、防禦建議

### 11.1 避免使用可預測個資作為密碼

姓名、生日、家人名稱、暱稱皆屬於高風險密碼成分。

### 11.2 採用高熵密碼或密碼管理器

應使用長度足夠且隨機性高的密碼，以避免被客製字典命中。

### 11.3 使用現代密碼雜湊方案

相較於 SHA-1，應改採：

- bcrypt
- scrypt
- Argon2

並加入唯一 salt，增加離線破解成本。

### 11.4 啟用多因素驗證

即使密碼遭還原，仍可降低帳號被直接接管的風險。

## 十二、結論

本題表面上是在做 hash 比對，實際上考的是 OSINT 與自訂字典攻擊。利用題目提供的個資與 CUPP 工具，可快速建立高度針對性的候選密碼集合，再由驗證腳本自動比對 SHA-1 雜湊，最終成功找出密碼 `Aj_15901990` 並取得 flag。此案例說明，只要密碼與個資關聯過深，即使以雜湊形式儲存，仍可能被低成本還原。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 核心弱點 | 弱密碼與個資關聯過高 |
| 利用條件 | 已知目標個資與對應 SHA-1 |
| 利用方式 | 以 CUPP 建立專屬字典並逐項比對 |
| 攻擊效果 | 還原原始密碼 |
| 本題成果 | 取得 `picoCTF{Aj_15901990}` |

## 使用工具

- Python 3
- CUPP
- Linux shell
- SHA-1 dictionary matching
