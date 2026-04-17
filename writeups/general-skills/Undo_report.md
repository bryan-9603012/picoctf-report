## Challenge Metadata

- **Platform:** picoCTF
- **Category:** General Skills
- **Difficulty:** Easy
- **Author:** Bryan
- **Date:** 2026-3-27

## 一、基本資訊

**題目名稱：** Undo  
**題目類型：** General Skills  
**平台：** picoCTF 2026  
**目標：** 還原多層 Linux 文字轉換，取得原始 flag

## 二、題目概述

本題提供一個可互動的 nc 服務，會逐步顯示已被轉換過的 flag，並在每一步提示最後施加了哪一種文字轉換。玩家需要輸入正確的 Linux 指令，將最後一層轉換反向還原，直到恢復原始 flag。

本題的核心不在於爆破，而在於：

- 讀懂每一步提示
- 理解常見 Linux 字串處理指令
- 依照正確順序逐層還原資料
- 最終組回完整 flag

## 三、分析目標

本次分析的主要目標如下：

- 確認遠端服務互動流程
- 判斷每一步對應的反向 Linux 指令
- 還原完整文字轉換鏈
- 成功取得 flag
- 說明題目設計邏輯與防禦意涵

## 四、環境觀察

題目提供一個 nc 連線入口，連上後會逐步顯示目前的 transformed flag 與提示文字，要求輸入可逆轉該步驟的 Linux command。

**觀察結果**

- 第 1 步提示字串為 Base64 encoded the string
- 第 2 步提示字串為 Reversed the text
- 第 3 步提示字串為 Replaced underscores with dashes
- 第 4 步提示字串為 Replaced curly braces with parentheses
- 第 5 步提示字串為 Applied ROT13 to letters

這表示題目不是一次性解碼，而是要求依照正確反向順序逐步輸入對應指令。

## 五、第一層分析：Base64 解碼

### 5.1 題目行為

第 1 步顯示目前 flag 為：

KXA2OTgxcHBxLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShTR1BicHZj

提示為：

Base64 encoded the string

### 5.2 對應還原方式

此時應輸入：

base64 -d

### 5.3 安全意義

Base64 並非加密，只是編碼。題目藉此測試使用者是否能正確辨識常見字元格式與還原方式。

## 六、第二層分析：字串反轉

### 6.1 題目行為

Base64 解碼後，題目顯示的字串為：

)p6981ppq-fa01g@ze0sfa4eG-gk3g-ta1ferirE(SGPbpvc

提示為：

Reversed the text

### 6.2 對應還原方式

此時應輸入：

rev

### 6.3 弱點本質

這一步只是單純的字串倒序，核心重點在於使用者需理解提示是描述「已做過的最後一步」，因此應輸入其反向操作。

## 七、第三層分析：底線與連字號替換

### 7.1 題目行為

反轉後，題目顯示：

cvpbPGS(Eriref1at-g3kg-Ge4afs0ez@g10af-qpp1896p)

提示為：

Replaced underscores with dashes

### 7.2 對應還原方式

因為原本的 underscore 被替換成 dash，所以現在要把 dash 換回 underscore：

tr '-' '_'

### 7.3 核心觀察

這一步若直接做 ROT13 會得到錯誤格式，因此必須先還原符號層級的改寫。

## 八、第四層分析：大括號與括號替換

### 8.1 題目行為

替換 dash 後，題目顯示：

cvpbPGS(Eriref1at_g3kg_Ge4afs0ez@g10af_qpp1896p)

提示為：

Replaced curly braces with parentheses

### 8.2 對應還原方式

此時要將括號改回大括號：

tr '()' '{}'

### 8.3 關鍵意義

這一步決定最後 flag wrapper 是否正確。若未先還原括號，最終結果會不是 picoCTF{...} 標準格式。

## 九、第五層分析：ROT13

### 9.1 題目行為

再往下還原後，題目顯示：

cvpbPGS{Eriref1at_g3kg_Ge4afs0ez@g10af_qpp1896p}

提示為：

Applied ROT13 to letters

### 9.2 對應還原方式

ROT13 是對稱變換，因此反向仍是：

tr 'A-Za-z' 'N-ZA-Mn-za-m'

### 9.3 還原結果

最終還原得到：

picoCTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_dcc1896c}

## 十、完整利用鏈

本題還原鏈如下：

- Base64 decode
- → reverse
- → tr '-' '_'
- → tr '()' '{}'
- → ROT13

## 十一、利用結果

取得的 flag：

picoCTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_dcc1896c}

## 十二、完整操作指令

```sh
base64 -d
rev
tr '-' '_'
tr '()' '{}'
tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

## 十三、成因分析

本題並非漏洞利用題，而是 Linux 文字轉換與可逆處理鏈的綜合練習。

### 13.1 容易出錯的點

- 誤以為整題只需一直做 Base64
- 未注意提示描述的是「最後一個已做過的轉換」
- 過早做 ROT13
- 未先修正符號，導致最後 flag wrapper 錯誤

### 13.2 技術重點

- Base64 只是編碼
- rev 可逆轉整串字元
- tr 可進行字元映射
- ROT13 為對稱替換

## 十四、防禦建議

雖然本題是教學型 challenge，但在實務上也反映出：

### 14.1 不應把簡單可逆轉換誤當保護機制

如 Base64、ROT13、字串反轉等方式，都不能提供真正的安全性。

### 14.2 混淆不等於加密

若敏感資料只是經過多層簡單轉換，仍可被依序還原。

## 使用工具

- nc
- base64
- rev
- tr
- ROT13
