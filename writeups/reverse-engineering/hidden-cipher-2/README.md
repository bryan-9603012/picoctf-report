## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-30

## 一、基本資訊

- **題目名稱：** Hidden Cipher 2
- **題目類型：** Reverse Engineering
- **平台：** picoCTF 2026
- **目標：** 理解題目中數學運算如何對假 flag 進行處理，並還原真正的 flag

## 二、題目概述

本題描述指出：「flag 就在你眼前，但只是某種程度上是如此。」下載程式包後可發現除了 binary `hiddencipher2` 外，還附有 `flag.txt`。直接查看 `flag.txt` 會得到：

```text
picoCTF{fake_flag}
```

這顯然是用來誤導使用者的假 flag。題目真正的關鍵在於理解 binary 所進行的「基本數學問題」，以及該數學答案如何被用來還原隱藏訊息。

## 三、分析目標

本次分析的主要目標如下：

1. 檢視題目附帶檔案內容
2. 判定 `flag.txt` 為誤導用資料
3. 找出數學運算與隱藏字串的關係
4. 還原真正 flag
5. 說明此題的編碼規則

## 四、環境觀察

解壓縮後可見：

```bash
unzip hiddencipher2.zip
ls
file hiddencipher2
file flag.txt
cat flag.txt
```

觀察結果：

- `hiddencipher2`：ELF 64-bit PIE executable，not stripped
- `flag.txt`：ASCII text
- `flag.txt` 內容：`picoCTF{fake_flag}`

這表示題目刻意把假 flag 放在明顯位置，真正解題必須依照 binary 的處理邏輯還原。

## 五、題目線索與核心觀念

題目描述強調：

- 先解一個 basic math problem
- 但真正重點是那個答案 **怎麼被使用**

實際整理出的數列為：

```text
6720, 6300, 5940, 6660, 4020, 5040, 4200, 7380, 6540, 3120, 6960, 6240, 5700, 5880, 3060, 6240, 2940, 6600, 6000, 5700, 5940, 2940, 6720, 6240, 3060, 6840, 5700, 5820, 6060, 5940, 3240, 3000, 3300, 3120, 5880, 7500
```

## 六、還原規則分析

將所有數字除以同一個公因數後，可得到標準 ASCII。

例如：

- `6720 / 60 = 112` → `p`
- `6300 / 60 = 105` → `i`
- `5940 / 60 = 99` → `c`
- `6660 / 60 = 111` → `o`

因此可得出規則：

```text
原數字 ÷ 60 = ASCII code
```

## 七、利用過程

### 7.1 將數列全部除以 60

將全部 36 個數字各自除以 60，得到 ASCII code 序列。

### 7.2 將 ASCII code 轉為字元

逐字轉換後可還原完整字串。

## 八、利用結果

成功還原真正 flag：

```text
picoCTF{m4th_b3h1nd_c1ph3r_aec6274b}
```

## 九、完整解題摘要

數學規則：

```text
encoded_value / 60 = ascii_code
```

再將 ASCII code 序列轉回字元即可得到最終 flag。

## 十、成因分析

本題本質上不是複雜加密，而是：

1. 先放置一個顯眼但錯誤的 `fake_flag`
2. 將真正字串的每個 ASCII 值乘上固定因數 60
3. 透過題目描述提示使用者注意「數學答案如何被使用」

也就是說，真正的 cipher 極為簡單，難點反而在於不要被假 flag 誤導。

## 十一、防禦建議

若從教育設計角度來看，這題示範了：

- 不要被明顯輸出的字串直接說服
- 要驗證題目提供資訊是否只是 decoy
- 面對簡單數列時，先思考是否存在固定比例、固定偏移或 ASCII 映射

## 十二、結論

本題利用假 flag 作為視覺誤導，再以非常簡單的線性轉換隱藏真實內容。只要觀察數列皆可被 60 整除，並將結果對應到 ASCII，即可快速還原最終 flag。這題的價值在於培養對 decoy 與簡單編碼規則的敏感度。

## 使用工具

- unzip
- file
- cat
- ASCII conversion
- basic arithmetic analysis
