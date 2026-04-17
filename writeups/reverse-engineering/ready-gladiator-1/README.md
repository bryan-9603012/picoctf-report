## Challenge Metadata

- **Platform:** picoCTF

- **Category:** Reverse Engineering / CoreWars

- **Difficulty:** Medium

- **Author:** Bryan

- **Date:** 2026-3-19

## 一、基本資訊

- **題目名稱：** Ready Gladiator 1

- **題目類型：** Reverse Engineering / CoreWars

- **平台：** picoCTF 2023

- **目標：** 撰寫一個 Redcode warrior，至少在 100 回合中擊敗對手 Imp 一次以取得 flag

## 二、題目概述

本題為 Core War 類型挑戰。題目提供對手 warrior Imp 的原始碼，要求玩家撰寫自己的 warrior 與其對戰。與 Ready Gladiator 2 必須 100 回合全勝不同，Ready Gladiator 1 只要求：

在 100 回合內至少贏 1 次

因此本題的要求相對寬鬆，不必追求完全 deterministic 的 counter，只要 warrior 具備足夠的攻擊能力，在多回合中有機會命中 Imp 即可。

## 三、分析目標

本次分析的主要目標如下：

1. 確認題目提供的 Imp warrior 行為
2. 理解 Imp 的弱點與可利用特性
3. 撰寫一個具備基本攻擊能力的 anti-imp warrior
4. 在遠端服務中至少取得 1 次勝利
5. 成功取得 flag，並整理本題的核心觀念

## 四、對手分析

題目提供的 imp.red 內容如下：

- ;redcode
- ;name Imp Ex
- ;assert 1
- mov 0, 1
- end
- 其核心行為如下：
- mov 0, 1
- 此指令會將目前位置的內容複製到下一格，因此 Imp 會持續向前複製自身。其特性如下：
- 程式極小
- 行為固定
- 會在 core memory 中持續向前延伸
- 若踩到 DAT 類型的致命指令，便會立即死亡

## 五、弱點判定

### 5.1 弱點描述

Imp 的弱點在於其結構極為單純，且運動模式規律固定。它不具備複雜控制流，也不會主動改變戰術，因此相當容易被「鋪炸彈」類型的 warrior 命中。

對本題而言，由於只需要贏一次，因此不必追求完全剋制 Imp 的結構，只要能在 core 中持續散播 DAT，便有機會在某一輪命中 Imp。

### 5.2 弱點類型

Fixed-behavior opponent exploitation

Bomber against linear replicator

Probabilistic anti-imp strategy

### 5.3 風險說明

若 warrior 只採用一般 sparse bombing，雖然可命中 Imp，但命中率不一定穩定。
因此：

在單回合中未必能立即擊殺

可能出現 tie

但由於本題只要求至少 1 勝，因此仍足以構成有效解法

## 六、攻擊思路

本題的基本思路為：

建立一顆 DAT 0,0 炸彈

在 core memory 中不斷將炸彈寫入不同位置

等待 Imp 前進時踩到炸彈

只要在 100 回合中至少發生 1 次成功命中，即可過題

這種作法本質上屬於 Dwarf / bomber 類 warrior，適合用來對付像 Imp 這種移動規律且缺乏防禦的對手。

## 七、利用過程

### 7.1 建立 anti-imp warrior

使用的 warrior 如下：

```
;redcode
;name Dwarf
;assert 1
```

```
add #4, 3
mov 2, @2
jmp -2
dat 0, 0
```

這支 warrior 的核心邏輯如下：

```
add #4, 3：調整 bombing 位置
```

```
mov 2, @2：將後方的 DAT 0,0 複製到目標位置
```

```
jmp -2：持續循環 bombing
```

```
dat 0, 0：作為致命炸彈
```

### 7.2 建立檔案

```bash
cat > antiimp.red <<'EOF'
;redcode
;name Dwarf
;assert 1
```

```
add #4, 3
mov 2, @2
jmp -2
dat 0, 0
EOF
```

### 7.3 提交到遠端服務

由於服務端要求 warrior 輸入完成後再送出一行單獨的 end 作為提交結束符，因此使用：

```bash
(cat antiimp.red; printf '\nend\n') | nc saturn.picoctf.net 62788
```

## 八、利用結果

成功提交 warrior 後，只要其中任一回合命中 Imp，即可取得 flag。

本題重點不在於每回合都贏，而在於：

warrior 能穩定運作

具備 bombing 能力

在多回合中至少成功擊殺一次 Imp

經實際測試，此類 Dwarf / bomber warrior 可滿足 Ready Gladiator 1 的條件。

## 九、完整 exploit 指令

```bash
cat > antiimp.red <<'EOF'
;redcode
;name Dwarf
;assert 1
```

```
add #4, 3
mov 2, @2
jmp -2
dat 0, 0
EOF
```

```bash
(cat antiimp.red; printf '\nend\n') | nc saturn.picoctf.net 62788
```

## 十、成因分析

本題能成功通過的原因在於：

Imp 的移動模式固定

它只會持續複製自己到下一格，缺乏機動性與應變能力。

Dwarf 類 warrior 能在多個位置鋪設致命炸彈

即使不是每次都命中，也有足夠機率在多回合中擊殺 Imp。

題目只要求至少 1 勝

因此只要 warrior 有基本 kill 能力，就足以通過。

換句話說，本題並不需要像 Ready Gladiator 2 一樣使用高度針對性的 imp-gate，只要能穩定地在 core 中散播 DAT，就已足夠。

## 十一、防禦建議

若從 Core War 設計角度來看，像 Imp 這種極簡線性 replicator 容易被 bomber 類 warrior 命中，因此若希望提高生存能力，可考慮：

### 11.1 增加行為變化

固定線性前進雖簡潔，但極易遭預測與針對。

### 11.2 避免單一路徑擴散

若 warrior 擴散路徑過於規律，bombing 類對手更容易命中。

### 11.3 增加多 process 或混合型結構

若能引入更複雜的 process 分裂或混合策略，會比純 Imp 更難被一般 bomber 針對。

### 11.4 根據題目需求選擇 warrior

本題的防守觀點同時反映了進攻觀點：

對付固定型對手時，不一定要最複雜的 warrior，只要選擇合適 counter 即可。

## 十二、結論

Ready Gladiator 1 的難點不高，關鍵在於理解：

對手是固定模式的 Imp

DAT 對 Imp 是致命的

只要 warrior 能夠在 core 中持續鋪炸彈，便有機會在多回合中命中對手

本題最終使用 Dwarf / bomber 類 warrior 完成解題。
與 Ready Gladiator 2 相比，本題不需要 100/100 全勝，因此不必採用高度針對性的 imp-gate；只要具備基本的 bombing 能力，即可順利過題。

本題的重要啟發是：

當題目只要求部分成功時，通用型攻擊策略往往就足夠，不必一開始就追求最精準、最專門的 counter。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 對手類型 | Imp |
| 對手核心指令 | mov 0, 1 |
| 解題策略 | Dwarf / bomber |
| 核心攻擊方式 | 在 core 中散播 DAT 0,0 |
| 題目需求 | 至少擊敗 Imp 1 次 |
| 最終結果 | 成功達成條件並取得 flag |
| 題目啟發 | 對固定模式對手，通用 bomber 已足夠應付寬鬆勝利條件 |

## 使用工具

- Linux shell
- nc
- Redcode / Core War warrior testing
- 手動 warrior 提交與結果觀察
