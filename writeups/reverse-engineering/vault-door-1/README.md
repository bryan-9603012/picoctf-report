## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-4-12

## 一、基本資訊

- **題目名稱：** vault-door-1
- **題目類型：** Reverse Engineering
- **平台：** picoCTF 2019
- **目標：** 還原正確密碼並通過 Vault Door 驗證

## 二、題目概述

本題提供一份 `VaultDoor1.java` 原始碼。程式會接收使用者輸入，去除 `picoCTF{}` 外層包裝後，將內容送入 `checkPassword()` 驗證。題目沒有使用真正的加密機制，而是將正確密碼拆散成多個條件，逐一檢查字元位置與內容是否正確。

表面上題目看起來條件很多，但實際分析後可發現，本題只是單純把正確字串拆成多個 `charAt(index)` 比對條件。只要將這些分散的條件整理回對應位置，即可直接還原出原始 password。

## 三、分析目標

本次分析的主要目標如下：

1. 確認 `checkPassword()` 的驗證邏輯
2. 找出每個索引位置對應的正確字元
3. 重新組合出完整 password
4. 驗證是否可正確通過程式檢查
5. 說明此題的核心是索引還原而非真正加密

## 四、靜態分析

題目核心程式如下：

```java
public boolean checkPassword(String password) {
    return password.length() == 32 &&
           password.charAt(0)  == 'd' &&
           password.charAt(29) == 'a' &&
           password.charAt(4)  == 'r' &&
           password.charAt(2)  == '5' &&
           password.charAt(23) == 'r' &&
           password.charAt(3)  == 'c' &&
           password.charAt(17) == '4' &&
           password.charAt(1)  == '3' &&
           password.charAt(7)  == 'b' &&
           password.charAt(10) == '_' &&
           password.charAt(5)  == '4' &&
           password.charAt(9)  == '3' &&
           password.charAt(11) == 't' &&
           password.charAt(15) == 'c' &&
           password.charAt(8)  == 'l' &&
           password.charAt(12) == 'H' &&
           password.charAt(20) == 'c' &&
           password.charAt(14) == '_' &&
           password.charAt(6)  == 'm' &&
           password.charAt(24) == '5' &&
           password.charAt(18) == 'r' &&
           password.charAt(13) == '3' &&
           password.charAt(19) == '4' &&
           password.charAt(21) == 'T' &&
           password.charAt(16) == 'H' &&
           password.charAt(27) == 'f' &&
           password.charAt(30) == '9' &&
           password.charAt(25) == '_' &&
           password.charAt(22) == '3' &&
           password.charAt(28) == 'f' &&
           password.charAt(26) == '7' &&
           password.charAt(31) == '4';
}
```

由上述邏輯可知，程式直接規定了每一個索引位置必須對應的字元，因此只需要將所有條件整理成索引表即可還原完整字串。

## 五、弱點判定

### 5.1 題目本質描述

本題並非傳統漏洞利用題，而是一題典型的字元索引還原題。其核心不是突破保護機制，而是找出：

- 哪個索引位置對應哪個字元
- 全部條件如何拼回完整 password
- 驗證條件是否存在真正的加密或混淆

### 5.2 核心技術點

- Index reconstruction
- Character mapping
- Reverse Engineering by code inspection

### 5.3 風險說明

若這種設計被誤認為安全機制，會造成錯誤的安全感。只要攻擊者能看到原始碼或分析驗證邏輯，就能直接依索引整理出正確密碼，不需要暴力破解，也不需要任何進階逆向技巧。

## 六、攻擊思路

原始驗證流程如下：

```text
password -> 逐一檢查 password.charAt(index) 是否等於指定字元
```

因此逆向思路為：

```text
已知每個 index 與對應字元
=> 依索引順序排列
=> 拼出完整 password
```

## 七、利用過程

### 7.1 整理索引與字元對應

```text
0  = d
1  = 3
2  = 5
3  = c
4  = r
5  = 4
6  = m
7  = b
8  = l
9  = 3
10 = _
11 = t
12 = H
13 = 3
14 = _
15 = c
16 = H
17 = 4
18 = r
19 = 4
20 = c
21 = T
22 = 3
23 = r
24 = 5
25 = _
26 = 7
27 = f
28 = f
29 = a
30 = 9
31 = 4
```

### 7.2 依序拼接

```text
d35cr4mbl3_tH3_cH4r4cT3r5_7ffa94
```

### 7.3 包回 picoCTF 格式

```text
picoCTF{d35cr4mbl3_tH3_cH4r4cT3r5_7ffa94}
```

## 八、利用結果

成功還原出正確 password，並得到 flag：

```text
picoCTF{d35cr4mbl3_tH3_cH4r4cT3r5_7ffa94}
```

## 九、完整驗證腳本

```python
chars = {
    0:'d', 1:'3', 2:'5', 3:'c', 4:'r', 5:'4', 6:'m', 7:'b',
    8:'l', 9:'3', 10:'_', 11:'t', 12:'H', 13:'3', 14:'_', 15:'c',
    16:'H', 17:'4', 18:'r', 19:'4', 20:'c', 21:'T', 22:'3', 23:'r',
    24:'5', 25:'_', 26:'7', 27:'f', 28:'f', 29:'a', 30:'9', 31:'4'
}
password = ''.join(chars[i] for i in range(32))
print(password)
print(f"picoCTF{{{password}}}")
```

## 十、成因分析

本題能被快速還原的主要原因，在於題目直接把所有驗證資訊以明顯且可讀的方式寫在程式內。

問題點如下：

1. 驗證條件直接暴露在程式中
   - 每一個索引位置應該對應的字元都能直接讀出。
2. 沒有使用任何不可逆處理
   - 題目沒有使用 hash、加密或其他保護方式。
3. 沒有額外混淆機制
   - 程式雖然看起來條件很多，但本質上只是固定字元比對。

## 十一、防禦建議

若在真實系統中要避免此類問題，可採取以下措施：

### 11.1 不要將敏感驗證內容直接寫在程式中

若將每個字元條件直接寫死，攻擊者只需閱讀程式碼即可得知正確輸入。

### 11.2 避免使用可直接還原的驗證邏輯

這類逐字元明文比對只會增加閱讀量，並不會真正提升安全性。

### 11.3 將真正驗證放在安全邊界內

敏感驗證應在可信任環境中完成，而不是讓所有細節直接暴露於可分析的程式中。

## 十二、結論

Vault Door 1 是一題典型的索引還原題。透過閱讀 `checkPassword()` 可發現，程式只是逐一檢查 32 個索引位置上的字元是否符合指定內容。由於所有條件都已明確寫在原始碼中，因此只需將其整理成索引表並重新排序，即可直接還原出原始 password。

此題說明了一個重要觀念：只要驗證邏輯完整暴露且內容可直接讀取，即使表面上條件繁多，也無法形成真正安全性。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題目核心 | Character index reconstruction |
| 驗證條件 | `password.charAt(index) == 指定字元` |
| 反推方式 | 依索引整理所有字元後重新拼接 |
| 利用條件 | 可讀取程式碼或逆向驗證邏輯 |
| 攻擊效果 | 直接還原正確密碼 |
| 本題成果 | 成功取得 `picoCTF{d35cr4mbl3_tH3_cH4r4cT3r5_7ffa94}` |

## 使用工具

- Java source code inspection
- Manual index mapping
- Python
