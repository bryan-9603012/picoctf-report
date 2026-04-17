# picoCTF Report — Predictable AES Key from Timestamp

## 基本資訊
- **題型**: Cryptography
- **核心觀念**: 弱金鑰衍生、可預測時間戳、AES-ECB
- **檔案**: `encryption.py`, `message.txt`

## 題目摘要
題目使用 `timestamp` 經過 SHA-256 後，取前 16 bytes 作為 AES 金鑰，再以 AES-ECB 加密明文。  
同時，題目又提供了「加密大約發生的時間」以及密文，因此可以直接針對提示時間附近的 timestamp 做暴力測試，還原出正確明文。

## 已知資訊
### 1. 題目提供的原始碼
原始程式顯示金鑰生成方式如下：

```python
key = sha256(str(timestamp).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
padded = pad(plaintext.encode(), AES.block_size)
ciphertext = cipher.encrypt(padded)
```

### 2. message.txt 內容
- Hint: The encryption was done around **1770242637 UTC**
- Ciphertext (hex):  
  `030ea2b59ea3cad39da9dfff761acc2598161c602243e2b0e9e571cee8285b87`

## 原始程式問題分析
題目給的原始 `encryption.py` 本身有錯誤：

1. `encrypt(plaintext, timestamp)` 內部又把 `timestamp` 覆蓋成 `time.time()`，導致參數失效。
2. `result = encrypt(plaintext, key)` 中的 `key` 未定義。
3. `print()` 使用了未定義的 `timestamp` 與 `ciphertext`。

因此，原始檔案無法直接執行，會出現 `NameError`。  
不過這不影響解題，因為**真正有價值的是加密邏輯本身**，而不是這支程式能不能直接跑。

## 漏洞成因
正常情況下，AES-128 的 key 應該具備高熵與不可預測性。  
但本題的 key 直接由 `timestamp` 推導而來：

- timestamp 是可預測資料
- 題目又給了「around 某個時間」
- 等於把 key space 大幅縮小成一小段整數區間

所以攻擊者不需要破解 AES，本質上只需要：

1. 枚舉提示時間附近的 timestamp
2. 對每個 timestamp 生成候選 key
3. 用該 key 解密密文
4. 檢查結果是否為有效明文

這屬於**弱金鑰衍生設計**。

## 解題思路
### Step 1: 取得提示時間與密文
從 `message.txt` 可得：
- `hint = 1770242637`
- `ciphertext = 030ea2b59ea3cad39da9dfff761acc2598161c602243e2b0e9e571cee8285b87`

### Step 2: 根據 timestamp 生成候選 key
對每個候選時間戳 `ts`：

```python
key = sha256(str(ts).encode()).digest()[:16]
```

### Step 3: 使用 AES-ECB 解密
```python
cipher = AES.new(key, AES.MODE_ECB)
pt = cipher.decrypt(ct)
```

### Step 4: 移除 padding 並檢查格式
因為原始加密前有做 PKCS#7 padding，所以解密後要：

```python
pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
```

接著判斷是否符合 `picoCTF{...}` 格式。

## Exploit 程式
```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

hint = 1770242637
ct = bytes.fromhex("030ea2b59ea3cad39da9dfff761acc2598161c602243e2b0e9e571cee8285b87")

for ts in range(hint - 10000, hint + 10001):
    key = sha256(str(ts).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
        if pt.startswith("picoCTF{") and pt.endswith("}"):
            print("timestamp =", ts)
            print("flag =", pt)
            break
    except:
        pass
```

## 解題結果
成功還原明文：

```text
picoCTF{sa3S_sEc9t_fbcf37a3}
```

## 攻擊成功原因
這題成功的原因不是 AES 本身弱，而是**金鑰生成方式太弱**：

- 金鑰依賴可預測的 timestamp
- 系統還額外洩漏大概時間
- 攻擊者只需在小範圍內暴力搜索即可

這相當於把原本 128-bit 不可行的爆破，降成幾千到幾萬次可行測試。

## 風險分析
### 影響
若真實系統採用類似設計，可能造成：

- 加密資料可被離線還原
- 機密資訊外洩
- 攻擊者可從時間線推測加密事件並還原 key

### 風險等級
**High**

原因：
- 攻擊成本低
- 不需已知明文
- 不需突破 AES
- 只需知道或估計加密時間

## 修補建議
1. **不要使用 timestamp 作為 key material**
   - 時間戳不是安全隨機來源。

2. **使用安全隨機數產生金鑰**
   - 例如 `os.urandom(16)`。

3. **若需要從密碼導出金鑰，應使用 KDF**
   - 如 PBKDF2、scrypt、Argon2。

4. **避免額外洩漏加密時間與內部細節**
   - 減少攻擊者縮小搜尋空間的機會。

5. **避免使用 ECB 模式**
   - 建議改用 AES-GCM 或 AES-CBC（搭配隨機 IV 與驗證機制）。

## 學習重點
這題主要訓練以下觀念：

- 不要把「可預測資料」當成密鑰來源
- 加密演算法安全，不代表整體設計安全
- 真正的弱點常出現在 key management / key derivation
- 題目中的 hint 可能就是縮小爆破空間的關鍵

## 結論
本題雖然使用 AES，但因為金鑰直接由 timestamp 導出，且題目還提供了近似時間，導致攻擊者可以在極小範圍內暴力列舉 key，最終還原明文並取得 flag。  
因此，本題的核心不是破解 AES，而是識別並利用**可預測金鑰來源**這個設計缺陷。
