## Challenge Metadata

- **Platform:** picoCTF

- **Category:** Reverse Engineering / Programming Concepts

- **Difficulty:** Easy

- **Author:** Bryan

- **Date:** 2026-03-20

## 一、基本資訊

- **題目名稱：** Ready Gladiator 0

- **題目類型：** Reverse Engineering / Core War Concept

- **平台：** picoCTF

- **目標：** 撰寫一個 warrior，讓自己在每一回合都必定失敗，且不能出現平手

## 二、題目概述

本題是一個與 Core War / Redcode 相關的題目。

使用者需要提交一段 Redcode warrior 到遠端伺服器，由伺服器讓該 warrior 與固定對手進行多回合對戰。

題目已知對手是：

Imp

也就是經典的自我複製 warrior：

```
mov 0, 1
```

本題要求不是要打贏對手，而是：

必須輸掉所有回合

不可以出現 tie

題目核心在於：

理解 Core War 的勝負條件

理解 Imp 的行為特性

利用 DAT 指令讓自己的 process 立即死亡

使對手穩定獲勝

## 三、分析目標

本次分析的主要目標如下：

1. 分析 Core War 的基本規則
2. 理解 Imp 為何不容易死亡
3. 確認平手產生的原因
4. 設計一個一定會輸的 warrior
5. 避免出現 tie

## 四、靜態分析

關鍵對手行為：

```
mov 0, 1
```

這條指令代表：

將目前位置的指令複製到下一格

若此指令持續執行，warrior 會不斷複製自己並向前延伸。

也就是：

Imp 具有持續自我複製的特性

若雙方都使用類似行為，通常會因為雙方都未死亡而導致平手。

本題另外一個關鍵指令是：

```
dat 0, 0
```

這段程式代表：

只要 process 執行到 DAT
→ 該 process 會立即死亡

也就是：

DAT 可作為立即終止 warrior 的方式

## 五、弱點判定

### 5.1 題目本質描述

本題並非傳統的 binary exploitation 題，而是觀念型對戰題。

核心不是利用記憶體漏洞，而是：

- 利用 Core War 的執行規則
- 控制自己 warrior 的存活時間
- 讓自己先於對手死亡

### 5.2 關鍵觀念類型

Core War Mechanics

Process Termination

Redcode Behavior Analysis

Self-Replication Concept

### 5.3 風險說明

原始流程：

Warrior 與對手進行多回合對戰

若雙方都持續存活：

Rounds 結束後 → 形成 ties

若我方先死亡：

Opponent wins

因此本題的重點不是攻擊對手，而是：

主動讓自己穩定死亡
→ 避免平手
→ 讓對手每回合獲勝

## 六、攻擊思路

解題流程如下：

分析題目要求
→ 確認不能 tie
→ 觀察對手是 Imp
→ 理解 Imp 會長時間存活
→ 放棄使用 Imp 類 warrior
→ 改用 DAT 作為第一條指令
→ 讓自己的唯一 process 一開始就死亡
→ 達成每回合穩定輸掉

## 七、利用過程

### 7.1 觀察錯誤做法

若提交：

```
mov 0, 1
```

則自己的 warrior 也會變成 Imp。

此時對戰情況為：

Imp vs Imp

結果通常是：

雙方都持續存活
→ 無法分出勝負
→ 100 rounds 全部 tie

### 7.2 確認平手原因

Imp 的特性是：

持續將自身複製到下一格

因此它通常不會自然死亡。

若雙方都使用相同行為：

雙方 process 都會一直存在

所以：

沒有任何一方先死亡
→ 產生 ties

### 7.3 建立正確 warrior

應改為提交：

```
;redcode
;name Loser
;assert 1
```

```
dat 0, 0
end
```

### 7.4 DAT 的效果

當 warrior 開始執行時，第一條指令即為：

```
dat 0, 0
```

執行後效果為：

目前 process 立即死亡

若該 warrior 僅有一個 process，則：

全部 process 死亡
→ warrior 判定失敗

### 7.5 對戰結果

我方 warrior：

開局即死亡

對手 Imp：

仍持續存活

因此每一局都會變成：

Warrior 1 loses
Warrior 2 wins

### 7.6 成功條件

成功輸出結果應接近：

- Rounds: 100
- Warrior 1 wins: 0
- Warrior 2 wins: 100
- Ties: 0

## 八、利用結果

成功透過 DAT 指令達成：

讓自己的 warrior 一開始即死亡

避免與 Imp 形成長時間平手

使對手於每一回合穩定獲勝

完成題目要求

## 九、完整 exploit 概念

start
→ execute DAT
→ process dies
→ no live process remains
→ lose round
→ opponent wins

或：

submit loser warrior
→ immediate self-termination
→ avoid tie
→ lose all rounds
## 十、成因分析

本題能解出的主要原因如下：

1. 題目要求是「必輸」

不是要擊敗對手，而是要：

穩定輸掉所有回合

2. Imp 本身不容易死亡

若模仿對手使用 mov 0,1

會因為雙方長時間存活而導致 tie

3. DAT 具備立即終止效果

DAT 一旦被執行，process 會直接死亡

因此非常適合用來設計：

必輸 warrior

## 十一、防禦建議

### 11.1 理解規則比盲目模仿重要

看到對手是 Imp，不代表應該直接使用相同 warrior。

必須先分析題目目標：

是求勝
還是求敗

### 11.2 區分「存活」與「終止」指令

```
mov 0,1 屬於持續延伸型指令
```

```
dat 0,0 屬於終止型指令
```

兩者用途完全不同。

### 11.3 注意題目中的勝負條件

本題真正限制是：

must lose all rounds, no ties

因此：

避免 tie
比單純不贏更重要

### 11.4 建立最小可行解

這題最穩定的做法不是複雜設計，而是：

最小化 warrior
→ 直接自毀
→ 確保穩定輸掉

## 十二、結論

本題展示了一個典型的 Core War 規則理解題。

使用者若直接模仿 Imp：

```
mov 0,1
```

則會因雙方都不易死亡而形成大量平手，無法滿足題目要求。

正確做法是利用：

```
dat 0,0
```

使自己的 warrior 在開始執行後立即終止，從而保證自己每局失敗、對手每局獲勝，成功完成題目要求。

本題重點不在複雜攻擊，而在：

正確理解執行規則
→ 正確利用終止指令
→ 設計出穩定必輸的 warrior

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 題目名稱 | Ready Gladiator 0 |
| 題目核心 | 設計一個必輸且不平手的 warrior |
| 對手類型 | Imp |
| 錯誤做法 | 使用 mov 0,1 導致 Imp vs Imp |
| 平手原因 | 雙方都持續存活直到 rounds 結束 |
| 正確做法 | 以 dat 0,0 作為第一條指令 |
| 攻擊效果 | 自己立即死亡，對手穩定獲勝 |
| 本題成果 | 達成 0 勝、100 敗、0 tie |

## 使用工具

- Linux shell
- nc
- Redcode
- Core War 基本觀念分析
