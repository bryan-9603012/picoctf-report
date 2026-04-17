## Challenge Metadata

- **Platform:** picoCTF

- **Category:** Reverse Engineering / CoreWars

- **Difficulty:** Medium

- **Author:** Bryan

- **Date:** 2026-3-19

## 一、基本資訊

- **題目名稱：** Ready Gladiator 2

- **題目類型：** Reverse Engineering / CoreWars

- **平台：** picoCTF 2023

- **目標：** 撰寫一個能在 100 回合內全部擊敗對手 Imp 的 Redcode warrior，取得 flag

## 二、題目概述

本題是 Core War 類型題目。題目提供對手 warrior Imp 的原始碼，並要求玩家撰寫自己的 Redcode warrior 與其對戰。與 Ready Gladiator 1 不同的是，本題不是只要贏一次，而是必須在 100 回合中全部獲勝。

題目表面上看起來像是在考驗如何提升 warrior 的攻擊效率，但實際測試後可發現，若只使用一般 Dwarf、bomber 或 clear 類型 warrior，通常只能取得部分勝利，其餘回合多半會變成 tie。真正的突破點在於理解 Imp 的固定行為模式，並使用更具針對性的 anti-imp 結構，也就是 imp-gate。

## 三、分析目標

本次分析的主要目標如下：

1. 確認題目提供的 Imp warrior 行為
2. 分析一般 bomber 類 warrior 為何無法達成 100/100 全勝
3. 找出能穩定剋制 Imp 的 anti-imp 結構
4. 撰寫並提交有效 warrior
5. 成功取得 flag，並說明其成因與核心觀念

## 四、對手分析

題目提供的 imp.red 內容如下：

- ;redcode
- ;name Imp Ex
- ;assert 1
- mov 0, 1
- end
- 其核心行為只有一條指令：
- mov 0, 1
- 這條指令會將目前位置的內容複製到下一格，因此 Imp 會持續向前延伸並規律前進。其特性如下：
- 程式極小
- 執行行為固定
- 會在 core memory 中穩定複製自身
- 若對手只使用一般 bomber，往往會因覆蓋率不夠而產生大量 tie

## 五、弱點判定

### 5.1 弱點描述

Imp 的最大弱點在於其行為模式完全固定。它不會隨機變化，也不具備複雜的控制流程，因此可以透過專門針對其運動方式的 warrior 進行結構性剋制。

本題真正的攻擊點不在於「更快地亂炸整個 core」，而在於：

預測 Imp 的規律移動

在其必經路徑或相鄰控制區建立致命結構

讓 Imp 穩定撞入 gate

### 5.2 弱點類型

Fixed-behavior opponent exploitation

Imp-gate / Anti-Imp Structure

Deterministic Core War Counter Strategy

### 5.3 風險說明

對於像 Imp 這種極簡 warrior，如果只採用一般 Dwarf 或 clear 類解法，雖然有一定機率命中，但通常無法保證每一回合都在時限內完成擊殺。因此即便不會輸，也容易出現大量 tie，進而無法通過題目要求的 100/100 全勝條件。

## 六、攻擊思路

初期測試時，先嘗試多種 bomber / clear 類 warrior，例如：

MultiDwarf

Double-bomb

GateClear

GateClear2

其中表現最好的通用型 warrior 類似如下：

```
;redcode
;name MD_best_so_far
;assert 1
```

start   spl 1
```
        spl 1
        spl 1
        spl 1
        spl 1
```

stone   add #4, 3
```
        mov 2, @2
        jmp -2
        dat 0, 0
end start
```

這類 warrior 的特徵是：

不太會輸給 Imp

有一定機率擊殺 Imp

但大量回合會變成 tie

代表性結果例如：

- Warrior 1 wins: 29
- Warrior 2 wins: 0
- Ties: 71
- 這表示一般 bomber 的問題並不是完全沒殺傷力，而是：
- 殺得不夠快，也不夠 deterministic

因此後續改變思路，從「大範圍亂炸」轉向「專門剋制 Imp 的結構」，也就是 imp-gate。

## 七、利用過程

### 7.1 建立 imp-gate warrior

最終成功使用的 warrior 如下：

```
gate equ wait-10
wait JMP wait,<gate
end wait
```

建立檔案：

```bash
cat > impgate.red <<'EOF'
gate equ wait-10
wait JMP wait,<gate
end wait
EOF
```

### 7.2 提交到遠端服務

由於服務端會要求使用者在輸入 warrior 後再額外輸入一行單獨的 end 作為提交結束符，因此使用以下方式送出：

```bash
(cat impgate.red; printf '\nend\n') | nc saturn.picoctf.net 57225
```

## 八、利用結果

送出後顯示結果如下：

Rounds: 100
Warrior 1 wins: 100
Warrior 2 wins: 0
Ties: 0
You did it!
```
picoCTF{d3m0n_3xpung3r_fc41524e}
```

成功取得 flag：

```
picoCTF{d3m0n_3xpung3r_fc41524e}
```

## 九、完整 exploit 指令

```bash
cat > impgate.red <<'EOF'
gate equ wait-10
wait JMP wait,<gate
end wait
EOF
```

```bash
(cat impgate.red; printf '\nend\n') | nc saturn.picoctf.net 57225
```

## 十、成因分析

本題能成功通過的核心原因，在於最終 warrior 並非一般意義上的 bomber，而是 專門對付 Imp 的 imp-gate。

問題的本質如下：

Imp 的行為過於固定

Imp 只會執行 mov 0, 1，也就是持續向前複製自身。

通用型 bomber 僅能部分命中

像 Dwarf、clear 這類 warrior 雖然能造成傷害，但通常仍帶有覆蓋率與時機問題，因此容易產生大量 tie。

Imp-gate 屬於結構性剋制

```
gate equ wait-10 與 JMP wait,<gate 的組合，能夠穩定建立對 Imp 極不利的控制區，使其在 100 回合內持續被剋制。
```

換句話說，本題不是單純比誰火力更大，而是比誰更能利用對手的固定模式。

## 十一、防禦建議

若從 Core War 設計角度來看，若不希望 warrior 像 Imp 一樣被結構性剋制，可考慮：

### 11.1 增加行為多樣性

過度單純、固定的 warrior 很容易被專門 counter。若 warrior 具備更多分支或多 process 行為，較不容易被 deterministic gate 完全壓制。

### 11.2 避免單一路徑前進模式

像 Imp 這種穩定直線複製行為，雖然小而經典，但也非常容易被針對。

### 11.3 混合型結構

若將 replicator、bomber、clear、gate 等概念混合使用，可降低被單一結構完全 counter 的風險。

### 11.4 針對對手特性選擇 warrior

本題也說明了，在 Core War 中最重要的不只是寫出強 warrior，而是根據對手特性選擇合適的 counter。

## 十二、結論

Ready Gladiator 2 的關鍵不在於單純增加 bombing 密度，而在於理解 Imp 的固定行為模式。前期雖然測試了多種 MultiDwarf、double-bomb、gate-clear 類 warrior，並取得部分勝利，但始終無法解決大量 tie 的問題。

最終成功的關鍵在於改用 imp-gate：

```
gate equ wait-10
wait JMP wait,<gate
end wait
```

此 warrior 並不是單純靠運氣命中，而是利用 Imp 規律前進的特性，建立專門的 anti-imp 結構，因此才能穩定達成：

Warrior 1 wins: 100

Warrior 2 wins: 0

Ties: 0

本題的重要啟發是：

對於固定模式的對手，最有效的解法往往不是更暴力，而是更精準的結構性剋制。

## 十三、附錄：關鍵觀念整理

| 項目 | 說明 |
| --- | --- |
| 對手類型 | Imp |
| 對手核心指令 | mov 0, 1 |
| 初期策略 | MultiDwarf / bomber / clear |
| 初期問題 | 雖能部分擊殺，但大量回合變成 tie |
| 真正有效策略 | Imp-gate |
| 最終 warrior | gate equ wait-10 / wait JMP wait,<gate / end wait |
| 攻擊效果 | 100 回合全勝 |
| 本題成果 | 成功取得 flag picoCTF{d3m0n_3xpung3r_fc41524e} |

## 使用工具

- Linux shell
- nc
- Redcode / Core War warrior testing
- 手動參數測試與結構比較
