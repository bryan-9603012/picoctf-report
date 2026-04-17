## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-4-12

## 一、基本資訊

- **題目名稱：** vault-door-4
- **題目類型：** Reverse Engineering
- **平台：** picoCTF 2019
- **目標：** 還原正確密碼並通過 Vault Door 驗證

## 二、題目概述

本題提供一份 `VaultDoor4.java` 原始碼。程式會將輸入字串轉為位元組陣列 `passBytes`，再與題目內建的 `myBytes` 陣列逐一比較。與前幾題不同的是，`myBytes` 裡的內容混用了十進位、十六進位、八進位與字元常值等表示法。

表面上題目看起來格式很多很亂，但實際分析後可發現，本題只是將同一串 ASCII 字元用不同進位方式寫出來。因此只要把每個值還原為對應字元，再按順序拼接即可得到正確 password。

## 三、分析目標

本次分析的主要目標如下：

1. 確認 `checkPassword()` 的驗證邏輯
2. 分辨 `myBytes` 中各種不同表示法
3. 還原每個位元組所代表的 ASCII 字元
4. 重新組合出完整 password
5. 說明此題的核心是表示法辨識而非真正加密

## 四、靜態分析

題目核心程式如下：

```java
public boolean checkPassword(String password) {
    byte[] passBytes = password.getBytes();
    byte[] myBytes = {
        106 , 85  , 53  , 116 , 95  , 52  , 95  , 98  ,
        0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
        0142, 0131, 0164, 063 , 0163, 0137, 061 , 063 ,
        'd' , 'f' , '6' , '1' , '8' , 'a' , '2' , '3' ,
    };
    for (int i=0; i<32; i++) {
        if (passBytes[i] != myBytes[i]) {
            return false;
        }
    }
    return true;
}
```

由上述邏輯可知，驗證條件其實就是：

```text
passBytes[i] == myBytes[i]
```

因此分析重點不是位元運算，而是將 `myBytes` 裡混合的表示法全部還原成正確的字元。

## 五、弱點判定

### 5.1 題目本質描述

本題並非傳統漏洞利用題，而是一題典型的編碼表示法還原題。其核心不是突破保護機制，而是找出：

- 各個數值是以哪種進位方式表達
- 這些值對應的 ASCII 字元是什麼
- 如何依原始順序重組出 password

### 5.2 核心技術點

- ASCII reconstruction
- Decimal / Hex / Octal conversion
- Character literal interpretation
- Reverse Engineering by code inspection

### 5.3 風險說明

若這種設計被誤認為安全機制，會造成錯誤的安全感。只要攻擊者理解不同進位表示法與 ASCII 對應，就能直接還原密碼內容，不需要暴力破解，也不需要進階逆向技巧。

## 六、攻擊思路

原始驗證流程如下：

```text
password -> getBytes() -> 與 myBytes 逐一比較
```

因此逆向思路為：

```text
已知 myBytes
=> 將十進位 / 十六進位 / 八進位 / 字元常值逐一轉回 ASCII
=> 依順序拼接
=> 得到原始 password
```

## 七、利用過程

### 7.1 第一段：十進位

```text
106 85 53 116 95 52 95 98
```

還原後為：

```text
jU5t_4_b
```

### 7.2 第二段：十六進位

```text
0x55 0x6e 0x43 0x68 0x5f 0x30 0x66 0x5f
```

還原後為：

```text
UnCh_0f_
```

### 7.3 第三段：八進位

```text
0142 0131 0164 063 0163 0137 061 063
```

還原後為：

```text
bYt3s_13
```

### 7.4 第四段：字元常值

```text
'd' 'f' '6' '1' '8' 'a' '2' '3'
```

還原後為：

```text
df618a23
```

### 7.5 拼接結果

```text
jU5t_4_bUnCh_0f_bYt3s_13df618a23
```

### 7.6 包回 picoCTF 格式

```text
picoCTF{jU5t_4_bUnCh_0f_bYt3s_13df618a23}
```

## 八、利用結果

成功還原出正確 password，並得到 flag：

```text
picoCTF{jU5t_4_bUnCh_0f_bYt3s_13df618a23}
```

## 九、完整驗證腳本

```python
my_bytes = [
    106, 85, 53, 116, 95, 52, 95, 98,
    0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f,
    0o142, 0o131, 0o164, 0o63, 0o163, 0o137, 0o61, 0o63,
    ord('d'), ord('f'), ord('6'), ord('1'), ord('8'), ord('a'), ord('2'), ord('3')
]
password = ''.join(chr(b) for b in my_bytes)
print(password)
print(f"picoCTF{{{password}}}")
```

## 十、成因分析

本題能被快速還原的主要原因，在於題目只是把相同資料用不同表示法寫出來，並沒有真正隱藏內容。

問題點如下：

1. 驗證資料直接暴露在程式中
   - `myBytes` 已完整包含正確密碼的每個位元組。
2. 混合進位表示法只是增加閱讀量
   - 十進位、十六進位與八進位都可以直接轉回 ASCII。
3. 沒有使用不可逆處理
   - 本題沒有使用 hash、加密或其他真正保護方式。

## 十一、防禦建議

若在真實系統中要避免此類問題，可採取以下措施：

### 11.1 不要把敏感資料以可讀形式直接放在程式中

即使改用不同進位寫法，本質上仍然是直接暴露資料。

### 11.2 避免將表示法混淆視為安全設計

不同進位只是呈現方式不同，並不會提供任何真正的防護能力。

### 11.3 敏感驗證應交由不可逆或可信任環境處理

真正的驗證不應依賴可被靜態分析直接還原的常數陣列。

## 十二、結論

Vault Door 4 是一題典型的表示法辨識與 ASCII 還原題。透過閱讀 `checkPassword()` 可發現，程式只是把正確密碼存放在 `myBytes` 中，並混用十進位、十六進位、八進位與字元常值來增加閱讀難度。由於所有資料都已直接暴露，因此只要逐一還原並拼接，即可取得原始 password。

此題說明了一個重要觀念：表示法混淆不等於安全。只要原始資料仍可直接被讀取與轉換，就能被快速還原。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題目核心 | Mixed-base ASCII reconstruction |
| 驗證條件 | `passBytes[i] == myBytes[i]` |
| 反推方式 | 將各種表示法逐一轉回 ASCII 後拼接 |
| 利用條件 | 可讀取程式碼或逆向驗證邏輯 |
| 攻擊效果 | 直接還原正確密碼 |
| 本題成果 | 成功取得 `picoCTF{jU5t_4_bUnCh_0f_bYt3s_13df618a23}` |

## 使用工具

- Java source code inspection
- ASCII conversion
- Python
