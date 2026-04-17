## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-4-12

## 一、基本資訊

- **題目名稱：** vault-door-6
- **題目類型：** Reverse Engineering
- **平台：** picoCTF 2019
- **目標：** 還原正確密碼並通過 Vault Door 驗證

## 二、題目概述

本題提供一份 `VaultDoor6.java` 原始碼。程式會接收使用者輸入，去除 `picoCTF{}` 外層包裝後，將內容送入 `checkPassword()` 驗證。與前幾題 Vault Door 系列類似，本題並非要暴力猜測密碼，而是需要透過閱讀程式邏輯，反推出真正的 password 字串。

表面上題目看起來像是在做某種加密驗證，但實際分析後可發現，程式只是將輸入位元組與固定常數 `0x55` 做 XOR，再與內建的位元組陣列 `myBytes` 比較。因此只要把這個過程反向推回去，即可直接還原正確答案。

## 三、分析目標

本次分析的主要目標如下：

1. 確認 `checkPassword()` 的驗證邏輯
2. 找出 `passBytes` 與 `myBytes` 的對應關係
3. 反推出原始 password
4. 驗證是否可正確通過程式檢查
5. 說明此題所涉及的 XOR 可逆特性

## 四、靜態分析

題目核心程式如下：

```java
public boolean checkPassword(String password) {
    if (password.length() != 32) {
        return false;
    }
    byte[] passBytes = password.getBytes();
    byte[] myBytes = {
        0x3b, 0x65, 0x21, 0xa , 0x38, 0x0 , 0x36, 0x1d,
        0xa , 0x3d, 0x61, 0x27, 0x11, 0x66, 0x27, 0xa ,
        0x21, 0x1d, 0x61, 0x3b, 0xa , 0x2d, 0x65, 0x27,
        0xa , 0x61, 0x37, 0x65, 0x61, 0x65, 0x65, 0x64,
    };
    for (int i=0; i<32; i++) {
        if (((passBytes[i] ^ 0x55) - myBytes[i]) != 0) {
            return false;
        }
    }
    return true;
}
```

由上述邏輯可知，驗證條件其實等價於：

```text
(passBytes[i] ^ 0x55) == myBytes[i]
```

也就是說：

```text
passBytes[i] = myBytes[i] ^ 0x55
```

這代表題目並未使用真正複雜的加密，而是採用了固定金鑰 XOR 的方式來遮蔽密碼內容。

## 五、弱點判定

### 5.1 題目本質描述

本題並非傳統漏洞利用題，而是一題典型的逆向還原題。其核心不是找系統弱點，而是找出：

- 輸入資料如何被轉換
- 程式如何進行比較
- 運算是否可逆
- 如何由已知常數反推出未知輸入

### 5.2 核心技術點

- XOR Reverse
- Fixed-key XOR
- Byte-level comparison
- Reverse Engineering by code inspection

### 5.3 風險說明

若這種設計被誤認為安全機制，會造成錯誤的安全感。固定 XOR 並不具備真正加密強度，只要攻擊者取得程式碼或可分析二進位邏輯，就能直接將常數反推回原文。

本題中，攻擊者完全不需要暴力破解，也不需要動態除錯，只要理解 XOR 可逆性，即可直接求出 password。

## 六、攻擊思路

原始驗證流程如下：

```text
password -> getBytes() -> passBytes
passBytes[i] ^ 0x55 -> 與 myBytes[i] 比較
```

因此逆向思路為：

```text
已知 myBytes[i]
=> 對每個位元組 XOR 0x55
=> 還原 passBytes[i]
=> 將位元組轉回 ASCII
=> 得到正確 password
```

這題的關鍵不在於爆破，而在於理解 XOR 的可逆特性：

```text
A ^ B = C
=> A = C ^ B
=> C = A ^ B
```

因此，只要知道 `myBytes` 與固定金鑰 `0x55`，就能還原出原始字串。

## 七、利用過程

### 7.1 取得題目中的 myBytes

```text
0x3b, 0x65, 0x21, 0x0a, 0x38, 0x00, 0x36, 0x1d,
0x0a, 0x3d, 0x61, 0x27, 0x11, 0x66, 0x27, 0x0a,
0x21, 0x1d, 0x61, 0x3b, 0x0a, 0x2d, 0x65, 0x27,
0x0a, 0x61, 0x37, 0x65, 0x61, 0x65, 0x65, 0x64
```

### 7.2 對每個位元組 XOR `0x55`

範例：

```text
0x3b ^ 0x55 = 0x6e = 'n'
0x65 ^ 0x55 = 0x30 = '0'
0x21 ^ 0x55 = 0x74 = 't'
```

依序處理全部 32 個位元組後，可得到完整字串：

```text
n0t_mUcH_h4rD3r_tH4n_x0r_4b04001
```

### 7.3 包回 picoCTF 格式

```text
picoCTF{n0t_mUcH_h4rD3r_tH4n_x0r_4b04001}
```

## 八、利用結果

成功還原出正確 password，並得到 flag：

```text
picoCTF{n0t_mUcH_h4rD3r_tH4n_x0r_4b04001}
```

## 九、完整驗證腳本

```python
my_bytes = [
    0x3b, 0x65, 0x21, 0x0a, 0x38, 0x00, 0x36, 0x1d,
    0x0a, 0x3d, 0x61, 0x27, 0x11, 0x66, 0x27, 0x0a,
    0x21, 0x1d, 0x61, 0x3b, 0x0a, 0x2d, 0x65, 0x27,
    0x0a, 0x61, 0x37, 0x65, 0x61, 0x65, 0x65, 0x64,
]

password = ''.join(chr(b ^ 0x55) for b in my_bytes)
print(password)
print(f"picoCTF{{{password}}}")
```

## 十、成因分析

本題能被快速還原的主要原因，在於題目採用了可逆且固定的運算方式來保護密碼。

問題點如下：

1. 使用固定 XOR 金鑰
   - 題目對所有位元組都使用相同的 `0x55`，不存在隨機性或複雜性。
2. 驗證邏輯直接暴露在程式中
   - 攻擊者可從原始碼中直接取得 `myBytes` 與 XOR 金鑰。
3. XOR 本身是可逆運算
   - 只要知道輸出與金鑰，即可還原輸入。
4. 沒有額外混淆或不可逆處理
   - 題目未使用 hash、加密函式、動態金鑰或其他防護方式。

## 十一、防禦建議

若在真實系統中要避免此類問題，可採取以下措施：

### 11.1 不要將敏感驗證邏輯明文寫在用戶端或可逆形式中

若把固定 XOR、固定常數陣列直接寫在程式內，攻擊者只要做靜態分析就能還原秘密內容。

### 11.2 避免使用可逆運算保護密碼

像 XOR、ROT、字元位移這種簡單可逆處理，都不適合作為真正的密碼保護方式。

### 11.3 使用安全雜湊或伺服端驗證

若要保護敏感值，應改用：
- 安全雜湊
- challenge-response
- server-side verification
- secret 不落地的驗證機制

### 11.4 增加混淆並不能等於安全

即使將資料拆成 byte array 或使用十六進位常數，也只是提高閱讀門檻，並不會提供真正安全性。

## 十二、結論

Vault Door 6 是一題典型的 XOR 逆向還原題。透過閱讀 `checkPassword()` 可發現，程式只是將輸入位元組與固定常數 `0x55` 做 XOR，再與內建陣列 `myBytes` 比對。由於 XOR 具有可逆性，因此只要將 `myBytes` 全部再 XOR 一次 `0x55`，就能直接還原出原始 password。

此題說明了一個重要觀念：可逆且固定的字元處理方式，無法真正保護秘密內容。一旦驗證邏輯與常數暴露，攻擊者便可透過靜態分析快速取得答案。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題目核心 | Fixed-key XOR reverse |
| 驗證條件 | `passBytes[i] ^ 0x55 == myBytes[i]` |
| 反推方式 | `passBytes[i] = myBytes[i] ^ 0x55` |
| 利用條件 | 可讀取程式碼或逆向驗證邏輯 |
| 攻擊效果 | 直接還原正確密碼 |
| 本題成果 | 成功取得 `picoCTF{n0t_mUcH_h4rD3r_tH4n_x0r_4b04001}` |

## 使用工具

- Java source code inspection
- Python
- XOR reverse reasoning
