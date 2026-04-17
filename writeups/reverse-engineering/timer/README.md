## Challenge Metadata

- **Platform:** picoCTF

- **Category:** Reverse Engineering

- **Difficulty:** Medium

- **Author:** Bryan

- **Date:** 2026-03-20

## 一、基本資訊

- **題目名稱：** timer

- **題目類型：** Reverse Engineering / Android APK Analysis

- **平台：** picoCTF 2023

- **目標：** 分析 APK 並找出隱藏於應用程式中的 flag

## 二、題目概述

本題提供一個 Android APK 檔案 timer.apk，題目描述指出需要透過分析 APK 來取得 flag。

一開始使用 file timer.apk 檢查檔案類型，可確認其本質為 ZIP 封裝格式。由於 APK 本身就是 Android 應用程式封包，因此可以透過解壓、字串搜尋與反編譯方式進行靜態分析。

本題的核心不在於動態操作或執行 App，而是：

分析 APK 內部結構

檢查 Manifest 與 DEX 內容

透過反編譯結果定位 flag

最終取得 flag

## 三、分析目標

本次分析的主要目標如下：

1. 分析 APK 的封裝結構
2. 確認應用程式內的重要檔案
3. 檢查 AndroidManifest.xml、classes.dex 等關鍵元件
4. 利用反編譯工具搜尋可疑字串
5. 成功找出 flag 所在位置

## 四、靜態分析

### 4.1 檔案類型確認

先以 file 指令確認檔案格式：

```bash
file timer.apk
```

輸出顯示：

timer.apk: Zip archive data, at least v0.0 to extract, compression method=store

這表示 timer.apk 本質上是 ZIP 壓縮封包，可直接解壓分析。

### 4.2 解壓 APK

將 APK 解壓後，可看到其主要內容如下：

time_out/AndroidManifest.xml
time_out/classes.dex
time_out/classes2.dex
time_out/classes3.dex
time_out/resources.arsc
time_out/META-INF/...

這代表該 App 至少包含：

Manifest 設定檔

三個 DEX bytecode 檔

資源索引檔

簽章與套件資訊

### 4.3 初步字串搜尋

一開始先對 APK 與 DEX 進行 strings 搜尋，嘗試找出以下關鍵字：

pico

flag

ctf

timer

secret

base64

xor

decode

初步搜尋雖然出現一些包含 Timer、Flags 的字樣，但多屬 Android UI 或框架內建字串，無法直接判定為 flag。

### 4.4 反編譯與全域搜尋

之後使用 JADX 將 APK 反編譯為可讀結構，再以 grep 對輸出結果進行遞迴搜尋：

```bash
grep -RniE "flag|pico|ctf|secret|timer|base64|xor|decode|CountDownTimer|postDelayed|sleep|System.currentTimeMillis" jadx_out
```

成功命中：

jadx_out/resources/AndroidManifest.xml:4: android:versionName="picoCTF{t1m3r_r3v3rs3d_succ355fully_17496}"

這表示 flag 並不在主要邏輯函式內，而是直接藏在 AndroidManifest.xml 的 versionName 欄位中。

## 五、弱點判定

### 5.1 弱點描述

本題並非傳統意義上的系統漏洞利用，而是典型的 APK 靜態分析題。其可利用點在於：

應用程式將敏感資訊直接嵌入封包內部

且該資訊位於 Manifest metadata 中

攻擊者只需解壓或反編譯 APK，即可直接取得 flag

### 5.2 類型判定

Hardcoded Sensitive Information

Insecure Application Packaging

Reverse Engineering Exposure

Metadata Disclosure

### 5.3 風險說明

若真實世界中的 Android App 將敏感資訊直接寫入：

AndroidManifest.xml

resources.arsc

strings.xml

Java / Kotlin 程式碼

DEX bytecode

則攻擊者可透過靜態分析輕易提取關鍵資訊，例如：

API Key

測試帳號

內部 URL

驗證邏輯

機密識別字串

本題中的 flag 即屬於這類「封包內敏感資訊暴露」。

## 六、攻擊思路

程式原始設計可能希望使用者聯想到：

timer

倒數邏輯

時間延遲

反轉計時流程

但實際分析後發現，真正關鍵並不在計時邏輯本身，而是：

先將 APK 解包

再用反編譯工具檢查資源與 metadata

最後在 Manifest 中直接找到 flag

攻擊核心在於：

不只分析 Java/Kotlin 程式碼

也要檢查 Android app 的 metadata 與 resources

## 七、利用過程

### 7.1 確認檔案格式

先以 file 指令確認 timer.apk 為 ZIP 封裝格式：

```bash
file timer.apk
```

### 7.2 解壓 APK

將 APK 解壓至資料夾：

```bash
unzip -o timer.apk -d time_out
```

### 7.3 確認重要檔案

檢查解壓後內容，確認存在：

AndroidManifest.xml

classes.dex

classes2.dex

classes3.dex

### 7.4 初步搜尋可疑字串

使用 strings 對 APK 與 DEX 進行搜尋，但未直接找到明確 flag。

### 7.5 使用 JADX 反編譯

將 APK 反編譯至 jadx_out：

```bash
jadx -d jadx_out timer.apk
```

### 7.6 全域搜尋關鍵字

對反編譯結果執行遞迴搜尋：

```bash
grep -RniE "flag|pico|ctf|secret|timer|base64|xor|decode|CountDownTimer|postDelayed|sleep|System.currentTimeMillis" jadx_out
```

### 7.7 取得 flag

最終於 jadx_out/resources/AndroidManifest.xml 中發現：

android:versionName="picoCTF{t1m3r_r3v3rs3d_succ355fully_17496}"

因此可確認 flag 為：

```
picoCTF{t1m3r_r3v3rs3d_succ355fully_17496}
```

## 八、利用結果

成功透過 APK 靜態分析與反編譯，於 AndroidManifest.xml 的 versionName 欄位中取得 flag。

## 九、完整 exploit 概念

取得 APK
→ 確認為 ZIP 封裝
→ 解壓 APK
→ 使用 JADX 反編譯
→ 搜尋 Manifest / resources / DEX
→ 發現 versionName 內嵌 flag
→ 取得 flag

## 十、成因分析

本題可被成功分析的主要原因如下：

### 10.1 敏感資訊直接硬編碼

flag 被直接放入應用程式封包內部，而非於執行期間安全產生或遠端取得。

### 10.2 Metadata 可被直接讀取

AndroidManifest.xml 屬於 APK 核心 metadata，經過反編譯後非常容易檢查。

### 10.3 缺乏封裝保護

即使 App 本身具備某些邏輯混淆，若敏感資訊直接存於 metadata，仍可被快速提取。

### 10.4 過度依賴表面題意

題目名稱為 timer，容易使分析者將注意力集中在計時邏輯、延遲執行或時間檢查上；但真正的關鍵其實藏在 Manifest 欄位。

## 十一、防禦建議

為避免此類問題，可採取以下措施：

### 11.1 不要將敏感資訊硬編碼於 APK

避免將以下資訊直接寫入：

Manifest

resource strings

Java/Kotlin source

DEX bytecode

### 11.2 將敏感邏輯移至後端

若需驗證或提供機密資料，應改由伺服器端回傳，不應內嵌於 client。

### 11.3 啟用混淆與縮減

使用 ProGuard / R8 進行：

符號混淆

字串保護

不必要程式碼刪除

雖然無法完全防止逆向，但可提高分析成本。

### 11.4 避免在 metadata 中存放機密資料

versionName、label、meta-data 等欄位都不應承載敏感資訊。

## 十二、結論

本題展示了一個典型的 Android APK 靜態分析案例。

雖然題目名稱為 timer，表面上可能讓人聯想到倒數、延遲或時間控制邏輯，但實際上 flag 被直接放置在 AndroidManifest.xml 的 versionName 屬性中。

此案例說明：

在逆向分析題中，除了主程式邏輯外，Manifest、resources 與 metadata 也必須納入檢查範圍。若只專注於 Java/Kotlin 程式碼，反而可能錯過最直接的解題線索。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題目名稱 | timer |
| 題目類型 | Reverse Engineering |
| 分析目標 | 由 APK 中找出 flag |
| 核心方法 | 解壓 + 反編譯 + 關鍵字搜尋 |
| 關鍵位置 | AndroidManifest.xml |
| 弱點名稱 | Hardcoded Sensitive Information |
| 利用條件 | 可取得 APK 並進行靜態分析 |
| 利用方式 | 搜尋反編譯後之 metadata |
| 攻擊效果 | 直接取得 flag |
| 本題成果 | 成功取得 picoCTF{t1m3r_r3v3rs3d_succ355fully_17496} |

## 使用工具

- Linux shell
- file
- unzip
- strings
- grep
- JADX
