import os
import ecdsa
import hashlib
import base58
import bech32
import pandas as pd
import requests
import concurrent.futures
import random
import time
from Crypto.Hash import RIPEMD

def ripemd160(data):
    h = RIPEMD.new()
    h.update(data)
    return h.digest()

# 然後原本這一行：
# ripemd160_pk = hashlib.new('ripemd160', sha256_pk).digest()

# 要改成：



# Telegram推送函數
def send_telegram_message(message, bot_token, chat_id):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': message
    }
    try:
        response = requests.post(url, data=payload)
        if response.status_code != 200:
            print(f"Telegram 發送失敗: {response.text}")
    except Exception as e:
        print(f"發送訊息錯誤: {e}")

# 隨機生成私鑰和地址的函數
def generate_private_key():
    return os.urandom(32)

def private_key_to_wif(private_key):
    extended_key = b'\x80' + private_key
    extended_key += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum)
    return wif.decode()

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x, y = vk.pubkey.point.x(), vk.pubkey.point.y()
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    compressed_public_key = prefix + x.to_bytes(32, 'big')
    return compressed_public_key

def public_key_to_p2pkh_address(public_key):
    sha256_pk = hashlib.sha256(public_key).digest()
    ripemd160_pk = ripemd160(sha256_pk)
    network_byte = b'\x00' + ripemd160_pk
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address_bytes = network_byte + checksum
    address = base58.b58encode(address_bytes)
    return address.decode()

def public_key_to_bech32_address(public_key):
    sha256_pk = hashlib.sha256(public_key).digest()
    ripemd160_pk = ripemd160(sha256_pk)
    witness_version = 0
    converted = bech32.convertbits(ripemd160_pk, 8, 5)
    address = bech32.encode('bc', [witness_version] + converted)
    return address

# 查詢地址餘額的函數
def query_balance(address, max_retries=5):
    url = f"https://blockstream.info/api/address/{address}"
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 429:
                print(f"遇到429限流，第{attempt+1}次，休息60秒...")
                time.sleep(60)
                continue
            response.raise_for_status()
            data = response.json()
            confirmed_balance = data['chain_stats']['funded_txo_sum'] - data['chain_stats']['spent_txo_sum']
            unconfirmed_balance = data['mempool_stats']['funded_txo_sum'] - data['mempool_stats']['spent_txo_sum']
            total_balance = confirmed_balance + unconfirmed_balance
            return total_balance
        except Exception as e:
            print(f"查詢{address}失敗: {e}，重試({attempt+1}/{max_retries})...")
            time.sleep(2 + attempt * 2)  # 每次重試，等待時間加倍
    return None

# 每次生成隨機地址並查詢餘額的處理函數
def process_one(bot_token, chat_id):
    private_key = generate_private_key()
    wif = private_key_to_wif(private_key)
    public_key = private_key_to_public_key(private_key)
    p2pkh_address = public_key_to_p2pkh_address(public_key)
    bech32_address = public_key_to_bech32_address(public_key)

    # 隨機延遲，裝人類行為
    time.sleep(random.uniform(0.2, 0.8))

    p2pkh_balance = query_balance(p2pkh_address)
    
    time.sleep(random.uniform(0.2, 0.8))

    bech32_balance = query_balance(bech32_address)

    if (p2pkh_balance and p2pkh_balance > 0) or (bech32_balance and bech32_balance > 0):
        result = {
            'Private Key (hex)': private_key.hex(),
            'WIF': wif,
            'Compressed Public Key (hex)': public_key.hex(),
            'P2PKH Address (1開頭)': p2pkh_address,
            'P2PKH Balance (sats)': p2pkh_balance,
            'Bech32 Address (bc1開頭)': bech32_address,
            'Bech32 Balance (sats)': bech32_balance
        }

        # 即時推送到 Telegram
        message = f"發現有餘額地址:\n\nP2PKH: {p2pkh_address}\n餘額: {p2pkh_balance} sats\nBech32: {bech32_address}\n餘額: {bech32_balance} sats"
        send_telegram_message(message, bot_token, chat_id)

        return result
    else:
        return None

# 批量生成地址並查詢餘額，結果寫入 CSV 文件
def batch_generate_addresses(num_addresses, output_csv='btc_addresses_found.csv', bot_token=None, chat_id=None, max_workers=10):
    records = []

    print(f"開始生成 {num_addresses} 組隨機地址並查詢餘額（多線程x{max_workers} 防封版）...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_one, bot_token, chat_id) for _ in range(num_addresses)]

        for idx, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            if result:
                records.append(result)
                print(f"[{idx+1}] 發現有餘額的地址！")
                # 即時寫入CSV
                df = pd.DataFrame([result])
                df.to_csv(output_csv, mode='a', header=not os.path.exists(output_csv), index=False)
            else:
                if (idx+1) % 50 == 0:
                    print(f"[{idx+1}] 目前尚未發現餘額...繼續搜尋...")

    if records:
        print(f"\n共找到 {len(records)} 個有餘額的地址！已儲存到 '{output_csv}'")
    else:
        print("\n沒有找到任何有餘額的地址。")

if __name__ == "__main__":
    bot_token = "7852353069:AAFEMafncSBX6vsdiO-gzYvx0W3cbC7BQyc"
    chat_id = "6131079077"
    
    num = int(input("你想要生成幾組隨機地址？（建議至少1000以上）: "))
    batch_generate_addresses(num, bot_token=bot_token, chat_id=chat_id)
