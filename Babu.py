import requests
import hashlib
import numpy as np
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from sympy import mod_inverse

def fetch_transactions(address):
    url = f"https://blockchain.info/rawaddr/{address}"
    try:
        data = requests.get(url).json()
        return data.get("txs", [])
    except:
        return []

def extract_public_keys(transactions):
    pubkeys = []
    for tx in transactions:
        for inp in tx.get("inputs", []):
            script = inp.get("script", "")
            if not script:
                continue
                
            try:
                # Basic scriptSig parsing for standard Pay-to-Public-Key-Hash (P2PKH)
                # Format is usually: [SigLength][Signature][PubKeyLength][PubKey]
                if script.startswith("4730") or script.startswith("4830"):
                    sig_len = int(script[0:2], 16) * 2 # Convert bytes length to hex characters
                    
                    # The public key length prefix follows right after the signature
                    pubkey_len_pos = 2 + sig_len
                    if len(script) > pubkey_len_pos + 2:
                        pubkey_len = int(script[pubkey_len_pos:pubkey_len_pos+2], 16) * 2
                        
                        # Extract the exact public key string
                        pubkey = script[pubkey_len_pos+2 : pubkey_len_pos+2+pubkey_len]
                        
                        # Only keep valid uncompressed (130 hex characters starting with 04)
                        if len(pubkey) == 130 and pubkey.startswith("04"):
                            pubkeys.append(pubkey)
            except Exception:
                continue # Skip malformed or unexpected script structures
                
    return pubkeys

def hex_to_point(pubkey_hex):
    if len(pubkey_hex) == 130 and pubkey_hex.startswith("04"):
        try:
            x = int(pubkey_hex[2:66], 16)
            y = int(pubkey_hex[66:130], 16)
            return Point(x, y, secp256k1)
        except ValueError:
            return None
    return None

def wormhole_attack(pubkeys):
    # Optimize by parsing points only once instead of calling hex_to_point twice per item
    points = []
    for pk in pubkeys:
        pt = hex_to_point(pk)
        if pt:
            points.append(pt)
            
    if len(points) < 2:
        return None
        
    base = points[0]
    for p in points[1:]:
        if p.x != base.x:
            # Mathematical validation checks
            try:
                offset = (p.y - base.y) * mod_inverse(p.x - base.x, secp256k1.q) % secp256k1.q
                private_key = (base.y - offset * base.x) % secp256k1.q
                return hex(private_key)
            except ValueError:
                continue
    return None

def main():
    address = input("Enter Bitcoin Address: ")
    print(f"🔎 Fetching Transactions for {address}")
    transactions = fetch_transactions(address)
    if not transactions:
        print("❌ No transactions found or API error.")
        return
    print(f"✅ {len(transactions)} Transactions Found!")
    
    pubkeys = extract_public_keys(transactions)
    if not pubkeys:
        print("❌ No valid uncompressed public keys found.")
        return
    
    print(f"✅ {len(pubkeys)} Valid Public Keys Extracted!")
    private_key = wormhole_attack(pubkeys)
    if private_key:
        print(f"🎯 Private Key Found: {private_key}")
        with open("found.txt", "a") as f:
            f.write(f"{address} : {private_key}\n")
    else:
        print("❌ Vulnerability Not Found!")

if __name__ == "__main__":
    main()
