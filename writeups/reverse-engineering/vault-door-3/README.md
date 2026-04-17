## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-4-12

## 一、基本資訊

- **題目名稱：** vault-door-3
- **題目類型：** Reverse Engineering
- **平台：** picoCTF 2019
- **目標：** 還原正確密碼並通過 Vault Door 驗證

## 二、題目概述

本題提供一份 `VaultDoor3.java` 原始碼。程式不直接將 `password` 與固定字串比較，而是先建立一個 `buffer[32]`，再透過多段 `for` 迴圈將輸入字元重新排列，最後比對 `buffer` 是否等於指定字串。

表面上題目看起來像是在做某種加密處理，但實際分析後可發現，本題只是對字元位置進行重排。因此只要理解每段迴圈如何搬動索引，就能反推出原始 password。

## 三、分析目標

本次分析的主要目標如下：

1. 確認 `checkPassword()` 的驗證邏輯
2. 分析 `buffer` 與 `password` 間的索引映射
3. 反推出原始 password
4. 驗證是否可正確通過程式檢查
5. 說明此題的核心是索引重排而非真正加密

## 四、靜態分析

題目核心程式如下：

```java
public boolean checkPassword(String password) {
    if (password.length() != 32) {
        return false;
    }
    char[] buffer = new char[32];
    int i;
    for (i=0; i<8; i++) {
        buffer[i] = password.charAt(i);
    }
    for (; i<16; i++) {
        buffer[i] = password.charAt(23-i);
    }
    for (; i<32; i+=2) {
        buffer[i] = password.charAt(46-i);
    }
    for (i=31; i>=17; i-=2) {
        buffer[i] = password.charAt(i);
    }
    String s = new String(buffer);
    return s.equals("jU5t_a_sna_3lpm11g54e_u_4_m4r042");
}
```

由上述邏輯可知，程式的最終目標是讓 `buffer` 變成：

```text
jU5t_a_sna_3lpm11g54e_u_4_m4r042
```

因此分析重點在於：這個 `buffer` 中每一個位置，對應到原始 `password` 的哪一個索引。

## 五、弱點判定

### 5.1 題目本質描述

本題並非傳統漏洞利用題，而是一題典型的索引映射逆向題。其核心不是突破保護機制，而是找出：

- `buffer[index]` 來自哪個 `password[index]`
- 多段迴圈如何重排字元
- 最終如何將固定字串反推回原始 password

### 5.2 核心技術點

- Index permutation reverse
- Buffer reconstruction
- Character reordering
- Reverse Engineering by code inspection

### 5.3 風險說明

若這種設計被誤認為安全機制，會造成錯誤的安全感。即使字元順序被打亂，只要攻擊者能看到程式碼，就能依照索引規則將字元重新還原，不需要暴力破解。

## 六、攻擊思路

原始驗證流程如下：

```text
password -> 依照多段迴圈搬到 buffer -> 與固定字串比較
```

因此逆向思路為：

```text
已知固定字串與每段迴圈的索引規則
=> 反推出 password 每個位置的值
=> 重組出原始 password
```

## 七、利用過程

### 7.1 固定字串

```text
jU5t_a_sna_3lpm11g54e_u_4_m4r042
```

### 7.2 依規則反推

第一段：

```text
buffer[0..7] = password[0..7]
```

第二段：

```text
buffer[8..15] = password[15..8]
```

第三段：

```text
buffer[16],18,...,30 = password[30],28,...,16
```

第四段：

```text
buffer[31],29,...,17 = password[31],29,...,17
```

### 7.3 還原結果

依照上述映射反推後，可得：

```text
jU5t_a_s1mpl3_an4gr4m_4_u_e45012
```

### 7.4 包回 picoCTF 格式

```text
picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_e45012}
```

## 八、利用結果

成功還原出正確 password，並得到 flag：

```text
picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_e45012}
```

## 九、完整驗證腳本

```python
target = "jU5t_a_sna_3lpm11g54e_u_4_m4r042"
password = ['?'] * 32

for i in range(0, 8):
    password[i] = target[i]

for i in range(8, 16):
    password[23 - i] = target[i]

for i in range(16, 32, 2):
    password[46 - i] = target[i]

for i in range(31, 16, -2):
    password[i] = target[i]

password = ''.join(password)
print(password)
print(f"picoCTF{{{password}}}")
```

## 十、成因分析

本題能被快速還原的主要原因，在於題目只是做了可追蹤的索引重排，而沒有真正隱藏驗證資訊。

問題點如下：

1. 重排規則完整暴露在程式中
   - 每一段 `for` 迴圈都能明確看出索引對應方式。
2. 最終比較字串直接給定
   - 攻擊者可以直接以目標字串為基礎進行反推。
3. 沒有使用不可逆處理
   - 本題只是調換位置，不涉及 hash 或真正加密。

## 十一、防禦建議

若在真實系統中要避免此類問題，可採取以下措施：

### 11.1 不要把可逆重排視為保護機制

單純的順序打亂並不能阻止攻擊者透過程式邏輯還原內容。

### 11.2 避免將完整驗證邏輯直接暴露

只要程式中同時包含重排規則與最終比較內容，就能被完整逆推。

### 11.3 敏感驗證應使用不可逆或伺服端驗證方式

真正的密碼驗證不應依賴這種可直接分析的字元重排邏輯。

## 十二、結論

Vault Door 3 是一題典型的索引映射逆向題。透過閱讀 `checkPassword()` 可發現，程式只是先將 `password` 依規則搬到 `buffer`，再把 `buffer` 與固定字串比較。由於整個搬運規則與目標字串都已暴露，因此只要反向追蹤索引，即可直接還原原始 password。

此題再次說明：只要驗證邏輯是可逆且完整暴露，字元重排本身並不能提供真正安全性。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題目核心 | Index permutation reverse |
| 驗證條件 | `buffer` 經重排後等於固定字串 |
| 反推方式 | 依各段迴圈索引映射反推 `password` |
| 利用條件 | 可讀取程式碼或逆向驗證邏輯 |
| 攻擊效果 | 直接還原正確密碼 |
| 本題成果 | 成功取得 `picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_e45012}` |

## 使用工具

- Java source code inspection
- Manual index mapping
- Python
