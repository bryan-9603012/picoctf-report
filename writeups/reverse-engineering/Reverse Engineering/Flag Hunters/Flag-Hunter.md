## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Reverse Engineering
- **Difficulty:** Easy
- **Author:** Bryan
- **Date:** 2025-12-13

### 一、基本資訊

**題目名稱：** Flag Hunters  
**題目類型：** Reverse Engineering  
**平台：** picoCTF  
**目標：** 透過操控程式輸入，使程式印出隱藏的副歌內容，取得 flag

### 二、題目概述

本題提供一個會輸出歌詞的程式，歌詞中包含 Verse（主歌） 與 Refrain（副歌） 的結構。程式在正常執行流程下只會印出部分內容，而 隱藏的副歌段落預設不會被輸出。

題目提示歌詞的跳轉方式類似 subroutine call（副程式呼叫），並且指出程式中存在一段未被預設執行的 hidden refrain。

經分析後可發現，程式會解析歌詞中的特殊指令（例如 REFRAIN、RETURN 等），並根據這些指令控制輸出流程。然而程式在解析使用者輸入時並未做嚴格的語法驗證，導致攻擊者可以透過輸入特定關鍵字來操控程式流程，使隱藏內容被輸出。

### 三、分析目標

本次分析的主要目標如下：

- 理解程式歌詞輸出與流程控制方式
- 找出程式流程控制的弱點
- 透過輸入操控程式邏輯
- 觸發隱藏副歌輸出
- 取得 flag

### 四、靜態分析

題目提供的程式碼中包含以下關鍵片段：

```
flag = open('flag.txt', 'r').read()

secret_intro = \
'''Pico warriors rising, puzzles laid bare,
Solving each challenge with precision and flair.
With unity and skill, flags we deliver,
The ether’s ours to conquer, '''\
+ flag + '\n'
```

由此可得知：

- 程式啟動時會讀取 flag.txt
- flag 會被加入到 secret_intro 字串中
- secret_intro 會成為整首歌的一部分

接著程式建立完整歌詞：

```
song_flag_hunters = secret_intro + '''
[REFRAIN]
...
CROWD (Singalong here!);
RETURN
```

歌詞中包含以下特殊指令：

項目 | 意義
---|---
REFRAIN | 呼叫副歌
RETURN | 結束副歌
CROWD | 等待使用者輸入

這表示程式會透過字串解析來模擬 副程式呼叫機制。

### 五、弱點判定

#### 5.1 弱點描述

程式在處理使用者輸入時，會將輸入內容解析為歌詞控制指令的一部分，但沒有對輸入進行嚴格過濾。

這導致攻擊者可以直接輸入包含 控制關鍵字 的字串，例如：

- RETURN

或包含指令分隔符號：

- ;

透過這種方式可以偽造歌詞控制流程。

#### 5.2 弱點類型

- Input Injection
- Logic Manipulation
- Improper Input Validation

#### 5.3 風險說明

由於程式會將使用者輸入當作歌詞流程的一部分進行解析，攻擊者可插入關鍵指令改變程式執行流程。

在本題中，攻擊者可以：

- 插入 RETURN
- 提前結束副歌流程
- 觸發隱藏段落輸出

最終導致包含 flag 的內容被顯示。

### 六、攻擊思路

程式歌詞中包含以下流程控制：

```
REFRAIN;
...
RETURN
```

若使用者輸入內容包含控制關鍵字，程式在解析時會將其當作合法流程的一部分。

因此攻擊者可以透過輸入：

```
test;RETURN 0
```

來插入一個 RETURN 指令，使程式提前返回並輸出隱藏內容。

### 七、利用過程

1. 首先連線到題目伺服器：

   ```sh
   nc verbal-sleep.picoctf.net 53372
   ```

2. 程式會輸出歌詞並等待使用者輸入。

3. 此時輸入以下 payload：

   ```
   test;RETURN 0
   ```

### 八、利用結果

輸入 payload 後，程式流程被改變，隱藏的副歌內容被輸出，並成功顯示 flag：

```
picoCTF{...}
```

### 九、完整 exploit 操作

```sh
nc verbal-sleep.picoctf.net 53372
```

輸入：

```
test;RETURN 0
```

即可取得 flag。

### 十、成因分析

本題弱點主要來自於 程式流程解析與輸入驗證設計不當。

問題點如下：

1. 使用者輸入未過濾
   - 程式未限制使用者輸入內容，導致可以輸入控制指令。
2. 控制語法直接暴露
   - 程式使用 REFRAIN、RETURN 等字串作為流程控制。
3. 字串解析模擬程式語言
   - 這種設計若沒有語法驗證，很容易被 injection。

### 十一、防禦建議

為避免類似問題，可採取以下措施：

#### 11.1 輸入驗證

限制使用者輸入格式，例如：

- 禁止 ;
- 禁止 RETURN
- 僅允許純文字

#### 11.2 使用安全解析方式

不要直接用字串解析來控制程式流程，應改為：

- 明確的函式呼叫
- 內部邏輯控制

#### 11.3 隱藏敏感資料

flag 不應直接嵌入歌詞字串中，而應只在合法流程下輸出。

### 十二、結論

本題透過歌詞模擬副程式呼叫流程，並在歌詞中使用 REFRAIN 與 RETURN 來控制輸出。然而程式在處理使用者輸入時缺乏驗證，導致攻擊者可透過輸入 test;RETURN 0 插入控制指令，改變程式流程並強制輸出隱藏副歌內容。

由於 flag 在程式初始化時已被嵌入到歌詞字串中，一旦隱藏段落被觸發，即可直接取得 flag。

### 十三、附錄：關鍵觀念整理

項目 | 說明
---|---
弱點名稱 | Input Injection
利用條件 | 使用者輸入未經驗證
利用方式 | 插入控制指令改變流程
攻擊效果 | 強制執行隱藏段落
本題成果 | 成功觸發副歌並取得 flag

## 使用工具

- nc
- Python
- code analysis