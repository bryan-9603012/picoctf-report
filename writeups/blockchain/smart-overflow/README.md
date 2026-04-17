## Challenge Metadata

- **Platform:** picoCTF
- **Category:** Blockchain
- **Difficulty:** Medium
- **Author:** Bryan
- **Date:** 2026-03-30

## 一、基本資訊

- **題目名稱：** Smart_Overflow
- **題目類型：** Blockchain
- **平台：** picoCTF 2026
- **目標：** 利用合約整數溢位條件觸發 reveal，並取得 flag

## 二、題目概述

本題提供一份 Solidity 合約 `IntOverflowBank.sol` 與鏈上互動實例。合約以 `uint256` 記錄使用者餘額，並宣稱理論上不可能取得 flag。然而分析程式碼後可發現，`deposit()` 在 Solidity 0.6.12 環境下未具備自動 overflow 檢查，導致攻擊者可藉由精心設計的兩次存款使餘額回捲為小值，進而讓 `revealed` 變成 `true`。

## 三、分析目標

本次分析的主要目標如下：

1. 理解 `deposit()` 的邏輯
2. 找出 reveal 條件可被觸發的原因
3. 設計最小步驟 exploit
4. 成功呼叫 `getFlag()` 取得 flag
5. 說明 Solidity 舊版本整數運算風險

## 四、原始程式碼分析

合約核心如下：

```solidity
pragma solidity ^0.6.12;

contract IntOverflowBank {
    mapping(address => uint256) public balances;
    address public owner;
    string private flag;
    bool public revealed;

    function deposit(uint256 amount) external {
        uint256 oldBalance = balances[msg.sender];
        balances[msg.sender] = balances[msg.sender] + amount;

        emit Deposit(msg.sender, amount);
        if (!revealed && balances[msg.sender] < amount) {
            revealed = true;
            emit FlagRevealed(flag);
        }
    }

    function getFlag() external view returns (string memory) {
        require(revealed, "Flag not revealed yet");
        return flag;
    }
}
```

## 五、弱點判定

### 5.1 弱點描述

`deposit()` 使用以下運算：

```solidity
balances[msg.sender] = balances[msg.sender] + amount;
```

在 Solidity 0.6.12 中，`uint256` 預設 **不會自動檢查 overflow**。因此當：

```text
oldBalance + amount > 2^256 - 1
```

時，結果會以模 `2^256` 回捲，而不會 revert。

### 5.2 額外問題

程式接著用：

```solidity
if (!revealed && balances[msg.sender] < amount)
```

作為觸發 reveal 的條件。正常情況下，存款後的新餘額應不可能小於剛存入的 `amount`，但若加法回捲為小值，該條件反而會成立。

### 5.3 弱點類型

- Integer Overflow
- Unsafe Arithmetic in Solidity < 0.8
- Logic Flaw Triggered by Overflow

## 六、攻擊思路

若初始餘額為 0，直接存入 `2^256 - 1` 不會 overflow，因此需要兩步：

1. 先 `deposit(1)`
2. 再 `deposit(2^256 - 1)`

第二次存款時計算如下：

```text
1 + (2^256 - 1) = 2^256 ≡ 0 mod 2^256
```

因此新的 `balances[msg.sender]` 變成 `0`，而：

```text
0 < 2^256 - 1
```

條件成立，`revealed = true`。

## 七、實例資訊

題目提供：

- **RPC URL：** `http://mysterious-sea.picoctf.net:62278`
- **Contract Address：** `0x6D8da4B12D658a36909ec1C75F81E54B8DB4eBf9`
- **Player Address：** `0x5Ef9936dd850cE6b6b0E2797247d6267aD4F5758`

由於本機未安裝 Foundry `cast`，改以 `web3.py` 腳本完成互動。

## 八、利用過程

### 8.1 建立 exploit 腳本

使用 Python 與 `web3.py` 連線 RPC，依序送出兩筆交易：

```python
from web3 import Web3

RPC_URL = "http://mysterious-sea.picoctf.net:62278"
MAX_UINT256 = 2**256 - 1

# [1] deposit(1)
# [2] deposit(MAX_UINT256)
# [3] getFlag()
```

### 8.2 實際交易順序

```text
deposit(1)
deposit(115792089237316195423570985008687907853269984665640564039457584007913129639935)
getFlag()
```

### 8.3 執行結果

腳本輸出顯示：

- `connected: True`
- `chain_id: 31337`
- 兩筆交易皆 `status: 1`
- `revealed = True`
- 成功讀出 flag

## 九、利用結果

成功取得 flag：

```text
picoCTF{Sm4r7_OverFL0ws_ExI5t_b5a187e5}
```

## 十、完整 exploit 腳本摘要

```python
from web3 import Web3

RPC_URL = "http://mysterious-sea.picoctf.net:62278"
PRIVATE_KEY = "<player private key>"
CONTRACT = "0x6D8da4B12D658a36909ec1C75F81E54B8DB4eBf9"
MAX_UINT256 = 2**256 - 1

# 連線後依序：
# contract.functions.deposit(1)
# contract.functions.deposit(MAX_UINT256)
# contract.functions.getFlag().call()
```

## 十一、成因分析

本題的根本原因在於：

1. 使用 Solidity `0.6.12`
2. 未使用 `SafeMath`
3. 未升級至 Solidity `0.8+` 的自動 overflow 檢查
4. 用錯誤邏輯將 overflow 作為 reveal 條件

換言之，原本設計者可能想藉由 `balances[msg.sender] < amount` 偵測異常，但在 unchecked arithmetic 環境中，這條件反而成為攻擊者主動可利用的觸發器。

## 十二、防禦建議

### 12.1 升級 Solidity 版本

使用 Solidity 0.8 以上版本，可讓整數 overflow 預設 revert。

### 12.2 採用 SafeMath

若必須維持舊版編譯器，應使用 SafeMath 類函式庫保護加減乘除。

### 12.3 重新設計驗證條件

不要以可能受 overflow 影響的算術結果作為安全狀態切換依據。

## 十三、結論

本題是典型的 Solidity 舊版整數溢位題。攻擊者不需要取得 owner 身分，也不需要直接讀取 private storage，只需利用 `deposit()` 未做 overflow 防護的特性，透過兩筆精心設計的交易使餘額回捲為 0，即可觸發 `revealed` 並順利取得 flag。這類題目非常適合用來理解舊版智慧合約的算術風險。

## 使用工具

- Solidity source review
- Python
- web3.py
- JSON-RPC interaction
