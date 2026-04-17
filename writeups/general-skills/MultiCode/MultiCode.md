## Challenge Metadata

- **Platform:** picoCTF
- **Category:** General Skills
- **Difficulty:** Easy
- **Author:** Bryan
- **Date:** 2026-3-28

## 一、基本資訊

- **題目名稱：** MultiCode
- **題目類型：** General Skills
- **平台：** picoCTF 2026
- **目標：** 逐層還原多重編碼後的訊息，取得最終 flag

## 二、題目概述

本題提供一段可疑訊息，並明確提示這不是加密，而是多層混淆。題目重點在於判斷每一層資料的表示格式，再逐層解碼，直到還原為最終明文。此題不需要爆破或逆向，只需要正確識別資料外觀並依序處理。

題目訊息如下：

```text
NjM3NjcwNjI1MDQ3NTMyNTM3NDI2MTcyNjY2NzcyNzE1ZjcyNjE3MDMwNzE3NjYxNzQ1ZjM0MzgzMTczMzAzNjM0NzAyNTM3NDQ=
```

## 三、分析目標

本次分析的主要目標如下：

1. 判斷原始資料的第一層編碼類型
2. 依序辨識每一層輸出的格式特徵
3. 還原最終可讀明文
4. 說明各層轉換邏輯與判定依據

## 四、分層分析

### 4.1 第一層：Base64

原始字串尾端帶有 `=`，且整體字元集合符合 Base64 特徵，因此先進行 Base64 解碼。

解碼結果為：

```text
637670625047532537426172666772715f72617030717661745f3438317330363470253744
```

### 4.2 第二層：Hex

第一層輸出由十六進位字元組成，長度也符合 hex byte 串格式，因此將其視為 hex 再轉一次。

結果得到：

```text
cvpbPGS%7Barfgrq_rap0qvat_481s064p%7D
```

### 4.3 第三層：URL Encoding

字串中出現 `%7B` 與 `%7D`，這是常見 URL encoding 形式，對應：

- `%7B` → `{`
- `%7D` → `}`

URL decode 後得到：

```text
cvpbPGS{arfgrq_rap0qvat_481s064p}
```

### 4.4 第四層：ROT13

此時可見字串外觀已接近 flag 格式，但前綴 `cvpbPGS` 明顯類似 ROT13 後的 `picoCTF`。  
因此再進行一次 ROT13 轉換，最終得到：

```text
picoCTF{nested_enc0ding_481f064c}
```

## 五、弱點判定

### 5.1 題目本質

本題不是系統漏洞利用題，而是編碼辨識題。其核心能力在於：

- 識別資料外觀
- 判斷下一步該用何種解碼方式
- 不被表面混淆誤導

### 5.2 技術重點

- Base64 常見於可列印資料封裝
- Hex 會呈現純十六進位字元
- URL encoding 會出現 `%xx`
- ROT13 常用於簡單字母位移混淆

## 六、解題思路

本題的最佳策略是觀察每層輸出的「外觀特徵」：

1. 看到尾端 `=` 與合法字符集，優先考慮 Base64
2. 若結果全是 0-9 與 a-f，則考慮 hex
3. 出現 `%7B`、`%20` 等形式時，考慮 URL decode
4. 若解碼後字串接近可讀英文但仍怪異，可再測試 ROT13

## 七、利用過程

### 7.1 手動逐層還原

原始資料：

```text
NjM3NjcwNjI1MDQ3NTMyNTM3NDI2MTcyNjY2NzcyNzE1ZjcyNjE3MDMwNzE3NjYxNzQ1ZjM0MzgzMTczMzAzNjM0NzAyNTM3NDQ=
```

步驟如下：

- Base64 decode
- Hex decode
- URL decode
- ROT13

### 7.2 Python 驗證腳本

```python
import base64, urllib.parse, codecs

s = "NjM3NjcwNjI1MDQ3NTMyNTM3NDI2MTcyNjY2NzcyNzE1ZjcyNjE3MDMwNzE3NjYxNzQ1ZjM0MzgzMTczMzAzNjM0NzAyNTM3NDQ="
step1 = base64.b64decode(s).decode()
step2 = bytes.fromhex(step1).decode()
step3 = urllib.parse.unquote(step2)
step4 = codecs.decode(step3, "rot_13")
print(step4)
```

## 八、利用結果

腳本輸出：

```text
picoCTF{nested_enc0ding_481f064c}
```

因此本題最終 flag 為：

```text
picoCTF{nested_enc0ding_481f064c}
```

## 九、完整利用指令

若以 Python 一行完成：

```bash
python3 -c "import base64,urllib.parse,codecs;s='NjM3NjcwNjI1MDQ3NTMyNTM3NDI2MTcyNjY2NzcyNzE1ZjcyNjE3MDMwNzE3NjYxNzQ1ZjM0MzgzMTczMzAzNjM0NzAyNTM3NDQ=';print(codecs.decode(urllib.parse.unquote(bytes.fromhex(base64.b64decode(s).decode()).decode()),'rot_13'))"
```

## 十、成因分析

本題可成功還原的原因不在於演算法強弱，而在於：

1. 所有層都只是可逆編碼
   - 沒有任何不可逆雜湊或真正加密
2. 每一層都有明顯格式特徵
   - Base64、hex、URL encoding、ROT13 都可由外觀快速辨識
3. 題目本質是資料表示法串接
   - 只要順序判斷正確，便可完整還原

## 十一、防禦建議

### 11.1 不要將可逆編碼當作保護機制

Base64、hex、URL encoding 與 ROT13 都不是安全機制，只是資料表示或簡易混淆。

### 11.2 需要保密時應使用真正加密

若目的是機密性，應採用經驗證的現代加密方案，而非堆疊多層可逆編碼。

### 11.3 避免安全性誤解

多層混淆可能增加閱讀難度，但不等同安全性，防守端不應將其視為保密手段。

## 十二、結論

本題是一個典型的多層編碼辨識題。透過觀察每層輸出的格式特徵，可依序判定應使用 Base64、hex、URL decode 與 ROT13 進行還原，最終成功取得 `picoCTF{nested_enc0ding_481f064c}`。此題強調的是資料表示與混淆辨識能力，而非密碼學意義上的破解。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 第一層 | Base64 |
| 第二層 | Hex |
| 第三層 | URL decode |
| 第四層 | ROT13 |
| 本題成果 | 取得 `picoCTF{nested_enc0ding_481f064c}` |

## 使用工具

- Python 3
- base64
- urllib.parse
- codecs
