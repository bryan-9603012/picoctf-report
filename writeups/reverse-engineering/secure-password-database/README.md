# 資安分析報告

picoCTF 2026 - heartbleed

## 一、基本資訊

- 題目名稱：heartbleed
- 題目類型：Reverse Engineering
- 平台：picoCTF 2026
- 目標：分析執行檔邏輯，找出隱藏 secret 與其對應 hash，最終取得 flag

## 二、題目概述

本題提供一個名為 `system.out` 的 ELF 64-bit 執行檔。程式表面上要求使用者先設定 password，接著詢問密碼長度，最後要求輸入 hash 才能存取帳號。

從互動流程來看，題目試圖讓使用者以為重點在於「自己輸入的 password」，但經過靜態分析可發現，真正被拿來驗證的並不是使用者前面輸入的密碼，而是程式內部從 `.rodata` 還原出的隱藏 secret。使用者若未看穿這點，就會被流程誤導。

## 三、分析目標

本次分析的主要目標如下：

1. 確認執行檔的基本結構與保護狀態
2. 分析 `hash()` 與 `make_secret()` 的功能
3. 找出 `.rodata` 中被混淆的 secret
4. 還原真正的驗證邏輯
5. 計算正確輸入值並取得 flag

## 四、環境觀察

使用 `file system.out` 可知：

- ELF 64-bit LSB pie executable
- dynamically linked
- not stripped

其中 `not stripped` 代表函式名稱尚保留，對靜態分析相當有利。

進一步使用 `objdump -d -M intel system.out` 可看到幾個關鍵函式：

- `hash`
- `make_secret`
- `main`

這表示程式作者並未刻意移除符號資訊，題目核心較偏向邏輯還原與資料流分析。

## 五、函式分析

### 5.1 `hash()`：djb2 雜湊函式

反組譯可觀察到 `hash()` 由 `0x1505` 開始，接著每輪執行：

- 左移 5 位
- 加回原值
- 再加上目前字元

其邏輯為：

```c
h = h * 33 + c;
```

這正是非常典型的 **djb2** hash。

可還原為：

```c
unsigned long hash(char *s) {
    unsigned long h = 5381;
    while (*s) {
        h = h * 33 + (unsigned char)*s;
        s++;
    }
    return h;
}
```

### 5.2 `make_secret()`：XOR 解密後再做 hash

`make_secret()` 的流程如下：

1. 逐 byte 讀取 `obf_bytes`
2. 對每個 byte 執行 `^ 0xaa`
3. 將結果寫入目標 buffer
4. 最後補上 `\0`
5. 將解出的字串丟入 `hash()`

這表示：

- `.rodata` 中存放的是混淆過的 secret
- 程式真正要用來驗證的值，是該 secret 的 djb2 hash

## 六、主程式流程分析

### 6.1 前半段：建立假資料庫內容

`main()` 一開始配置 0x5a bytes 的 heap 空間，之後把 `obf_bytes ^ 0xaa` 的結果寫到該空間偏移 `+0x3c` 的位置。

這代表程式內部維護了一塊類似「帳號資料」的結構，而隱藏 secret 被放在其中某一區段。

### 6.2 第一段使用者輸入

程式先要求使用者輸入 password，之後把這段輸入複製進 heap 區塊中。

表面上看來像是系統要把使用者輸入的資料存入資料庫，但這其實只是用來誤導分析方向。

### 6.3 第二段使用者輸入

接著程式詢問 password 的長度，讀入後會顯示：

```text
You entered: %d
```

之後還會逐字輸出「Your successfully stored password」之類的內容，看起來像是在展示資料庫裡儲存的結果。

### 6.4 第三段使用者輸入：真正的驗證點

後半段程式再次讀取輸入，並使用類似 `strtol(input, &endptr, 10)` 的方式把字串轉成 **十進位整數**。

這說明真正的驗證輸入不是 password 字串，而是一個 **十進位 hash 值**。

也就是說，前面讓你輸入 password 與長度的流程，實際上只是煙霧彈；真正關鍵在於最後是否能輸入內部 secret 的 hash。

## 七、`.rodata` 分析

透過：

```bash
objdump -s -j .rodata system.out
```

可在 `0x2008` 位置看到 `obf_bytes`：

```text
c3 ff c8 c2 92 9b 8b c0 80 c2 c4 8b
```

對每個 byte 執行 `^ 0xaa` 後，可得出真正的 secret：

```text
iUbh81!j*hn!
```

## 八、雜湊計算

使用與程式相同的 djb2 邏輯計算：

```text
iUbh81!j*hn!
```

可得到十進位結果：

```text
15237662580160011234
```

十六進位則為：

```text
0xd3770d6251b31be2
```

因此最後應輸入的正確值為：

```text
15237662580160011234
```

## 九、利用過程

### 9.1 觀察程式結構

先以 `file`、`nm`、`objdump` 等工具確認：

- 為 64-bit ELF
- 未 strip
- 存在 `hash`、`make_secret`、`main`

### 9.2 還原 `hash()` 邏輯

由反組譯確認 `hash()` 為 djb2。

### 9.3 分析 `.rodata`

從 `objdump -s -j .rodata system.out` 取出 `obf_bytes`，並對其逐 byte XOR `0xaa`，解出 secret：

```text
iUbh81!j*hn!
```

### 9.4 計算最終 hash

將 secret 代入 djb2，得到：

```text
15237662580160011234
```

### 9.5 輸入正確值

在程式最後要求輸入 hash 時，輸入上述十進位值，即可成功通過驗證並讀出 flag。

## 十、利用結果

成功取得 flag：

```text
picoCTF{d0nt_trust_us3rs}
```

## 十一、核心觀念整理

### 11.1 題目名稱的提示意義

本題最後取得的 flag 為：

```text
picoCTF{d0nt_trust_us3rs}
```

這正好點出本題最重要的安全觀念：

**不要信任使用者輸入，也不要被程式表面流程誤導。**

從攻擊者角度來看，這題也在提醒分析者：

- 程式要求你輸入的內容，不一定是真正參與驗證的資料
- 程式顯示給你的資訊，可能只是煙霧彈
- 必須回到二進位本身，確認真正的資料流與驗證條件

### 11.2 靜態分析的重要性

若只依賴執行程式的互動畫面，會很容易以為重點在：

- 猜測 password
- 嘗試不同長度
- 思考資料庫格式

但透過 `objdump` 與 `.rodata` 分析後，可以清楚發現：

- 真正的 secret 根本不來自使用者輸入
- 驗證資料其實早已內建在程式中

### 11.3 Reverse 題常見手法

本題結合了幾種常見 reverse engineering 題型技巧：

- 保留符號名稱，降低進入門檻
- 以字串與互動流程誤導使用者
- 將重要資料放在 `.rodata`
- 透過簡單 XOR 混淆隱藏字串
- 再搭配常見 hash 函式增加表面複雜度

### 11.4 安全意義

本題從防禦角度也有啟示：

- 若敏感邏輯完全寫死在 client-side 或 binary 中，分析者終究能還原
- 單純的 XOR 混淆並不能保護真正的秘密
- 將「祕密值」直接內建在程式中，並不是安全的驗證設計

## 十二、防禦建議

### 12.1 不要將真正的 secret 直接硬編碼在程式內

若驗證依賴真正敏感資料，應避免把 secret 直接存放於 binary 的 `.rodata` 中。即使做了簡單 XOR 混淆，也很容易被逆向還原。

### 12.2 混淆不等於安全

XOR、位移、簡單編碼等手法只能增加分析成本，不能作為真正的保護機制。

### 12.3 驗證應盡量放在受保護的伺服器端

若關鍵驗證完全在本地程式中完成，攻擊者只要能取得 binary，就有機會還原整個邏輯並重建正確輸入。

## 十三、結論

本題表面上看似要求使用者自行設定 password 並輸入對應 hash，實際上真正參與驗證的資料完全不來自使用者，而是程式內部從 `.rodata` 解出的隱藏 secret。

透過靜態分析可確認：

- `hash()` 為 djb2
- `make_secret()` 會將 `obf_bytes ^ 0xaa` 解成明文 secret
- 驗證最終比對的是該 secret 的十進位 hash 值

只要還原 `.rodata` 中的 `obf_bytes`，解出：

```text
iUbh81!j*hn!
```

再計算其 djb2 hash：

```text
15237662580160011234
```

即可成功通過驗證並取得 flag `picoCTF{d0nt_trust_us3rs}`。

本題是一個很典型的 reverse engineering 練習，重點不在爆破，而在於理解程式真正使用了什麼資料、如何轉換，以及最後到底在比對什麼。

## 十四、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題目核心 | 還原內建 secret 並計算對應 hash |
| 關鍵函式 | `hash()`、`make_secret()` |
| secret 隱藏方式 | `.rodata` 中的 `obf_bytes`，逐 byte XOR `0xaa` |
| hash 演算法 | djb2 |
| 真正 secret | `iUbh81!j*hn!` |
| 最終輸入值 | `15237662580160011234` |
| 本題成果 | 成功通過驗證並取得 flag |
