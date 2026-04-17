## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-30

## 一、基本資訊

- **題目名稱：** Autorev 1
- **題目類型：** Reverse Engineering
- **平台：** picoCTF 2026
- **目標：** 自動解析遠端提供的 ELF hex，快速求出正確 secret 並取得 flag

## 二、題目概述

本題只提供一個 `nc` 服務，題目名稱與敘述均強調「速度」。實際連線後可發現，服務會不斷送出一段 ELF 執行檔的十六進位內容，並在最後詢問：

```text
What's the secret?
```

題目要求在每輪極短時間內從該 ELF 中找出正確答案並回送。手動分析雖可解，但效率不足，因此最佳做法是建立自動化腳本。

## 三、分析目標

本次分析的主要目標如下：

1. 確認遠端輸出內容為 ELF hex dump
2. 找出 binary 中 secret 常數的固定位置
3. 將該常數轉為十進位 unsigned int
4. 自動將答案送回遠端
5. 完成多輪挑戰並取得最終 flag

## 四、行為觀察

連線指令如下：

```bash
nc mysterious-sea.picoctf.net 52183
```

觀察發現：

- 每一輪都會提供一個小型 ELF binary 的十六進位字串
- binary 內容中可見 `What's the secret?`、`%u`、`Correct!`、`Nice try :(` 等字串
- 若回答錯誤，會直接失敗
- 若回答正確，則進入下一輪或最終輸出 flag

## 五、靜態分析

將其中一輪的 hex 還原後，可從反組譯中看到類似指令：

```asm
c7 45 fc 71 6f 78 f1
```

這對應：

```asm
movl $0xf1786f71, -0x4(%rbp)
```

程式後續再用：

```c
scanf("%u", &input);
if (input == secret) {
    puts("Correct!");
}
```

由此可知：

1. 題目真正要找的是一個 **32-bit 常數**
2. 該常數位於 `movl $imm32, -0x4(%rbp)`
3. 因 `scanf("%u")` 的關係，答案必須以 **十進位 unsigned int** 回答

## 六、資料格式關鍵

x86 採 little-endian，因此若看到：

```text
c745fc401cb24d
```

其中立即數部分為：

```text
40 1c b2 4d
```

實際值需反轉為：

```text
0x4db21c40
```

再轉十進位即可得到最終答案。

## 七、自動化思路

由於每輪 binary 結構固定，因此可直接以正規表示式在整段 hex 中搜尋：

```text
c745fc????????c745f800000000
```

其中 `????????` 即為 little-endian 的 4 bytes secret。將其轉換流程自動化後，即可穩定秒解。

## 八、利用過程

### 8.1 撰寫自動化腳本

撰寫 Python 腳本完成以下步驟：

1. 連接 `nc` 服務
2. 接收遠端輸出直到 `What's the secret?`
3. 以 regex 萃取 `c745fc([0-9a-f]{8})`
4. 將 4 bytes 以 little-endian 解為 unsigned int
5. 送回答案
6. 重複至取得 flag

### 8.2 核心邏輯

```python
imm_bytes = bytes.fromhex(imm_le)
secret = int.from_bytes(imm_bytes, byteorder="little", signed=False)
```

## 九、利用結果

自動化完成多輪解析後，成功取得 flag：

```text
picoCTF{4u7o_r3v_g0_brrr_78c345aa}
```

## 十、完整 exploit 摘要

```bash
python3 autorev1_solver.py mysterious-sea.picoctf.net 52183
```

腳本核心策略：

- 抓 ELF hex
- 解析 `movl $imm32, -0x4(%rbp)`
- little-endian 轉換
- 轉 unsigned 十進位
- 自動回答

## 十一、成因分析

本題的安全性依賴於：

1. 使用者無法即時人工分析每輪 ELF
2. 使用者不熟悉 x86 little-endian 與 immediate value 讀法
3. 使用者不會建立自動化流程

但由於 binary 結構高度固定，secret 常數在指令中的位置也極為規律，因此一旦建立規則，即可將整題完全自動化。

## 十二、防禦建議

若真要提高題目抗自動化能力，可考慮：

### 12.1 增加多樣化指令生成

避免 secret 永遠固定出現在同一個 opcode pattern 中。

### 12.2 改變驗證邏輯

可使用簡單運算、分支或混淆，讓使用者不能僅憑 regex 即完成解題。

### 12.3 加入動態互動

例如讓 secret 經過額外變換或與前一輪結果關聯，以增加腳本撰寫難度。

## 十三、結論

本題是典型的「可腳本化 reverse engineering」題。核心並不在深度逆向，而在快速辨識 ELF 內部驗證模式，並將該模式自動化。透過分析 `movl $imm32, -0x4(%rbp)` 與 `scanf("%u")` 的配合關係，可穩定提取每輪 secret，最終高效率取得 flag。

## 使用工具

- netcat
- Python
- regex
- endian conversion
- basic x86-64 instruction pattern recognition
