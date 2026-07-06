---
title: "Simplicity CTF"
ctf: "Arvolear simplicity-ctf"
date: 2026-07-06
category: crypto/forensics/blockchain
difficulty: hard
points: "Liquid reward: 1,000,000 sats"
flag_format: "spent transaction"
author: "Harshycn, post-solve reconstruction"
---

# Simplicity CTF

## Summary

The public PRs are not the real Liquid-mainnet solution. They redeploy the contracts in the local Simplex test harness, issue their own auth asset, and use the test signer's key as `OWNER_PUBKEY`.

This writeup is a post-spend reconstruction. Harshycn was not the on-chain reward claimant; the reward had already been spent by another solver when this analysis was written.

The real on-chain solution is transaction:

```text
d42f6bc30f4eac43fbe5dcd11552754307150c7654a4867a2019f31cbedf30d3
```

It spends funding transaction:

```text
aa52a138a0e193c8530e1195b201c7139de194decc0ff3bb01489adbe814095c
```

Funding vout 12 is the reward contract and funding vouts 0..11 are the 12 `asset_lock` contracts. The spend uses the reward as input 0 and the 12 locks as inputs 1..12, then places 12 units of the auth asset into output 0.

## Key Observation

`asset_lock.simf` checks two things:

```text
bip_0340_verify(OWNER_PUBKEY, sig_all_hash(), signature)
current_script_hash() == get_script_hash_for_storage(nonce)
```

The `nonce` is a `u64`, but storage encodes it as:

```text
u256((0, 0, 0, nonce))
```

So a nonce is exactly 8 controllable bytes inside the storage leaf. In the real spend, each `asset_lock` witness starts with a 64-byte Schnorr signature and ends with this 8-byte nonce. The 12 leaked nonce values are ASCII words padded with zero bytes:

| Funding vout | Nonce hex | Word |
|---:|---|---|
| 0 | `686f6c6500000000` | `hole` |
| 1 | `6172740000000000` | `art` |
| 2 | `6b6e696665000000` | `knife` |
| 3 | `77616c6e75740000` | `walnut` |
| 4 | `6c616e6775616765` | `language` |
| 5 | `636f6f6c00000000` | `cool` |
| 6 | `626f72726f770000` | `borrow` |
| 7 | `626f617264000000` | `board` |
| 8 | `726976616c000000` | `rival` |
| 9 | `73696c6b00000000` | `silk` |
| 10 | `6f63746f62657200` | `october` |
| 11 | `626f790000000000` | `boy` |

This gives the BIP39 mnemonic:

```text
hole art knife walnut language cool borrow board rival silk october boy
```

The intended pre-spend route is therefore to enumerate BIP39 English words, encode each word as `word_bytes || zero_padding` to 8 bytes, compute the corresponding `asset_lock` script, and match those scripts against the 12 funding outputs. BIP39 English words are at most 8 characters, which fits the `u64` witness exactly.

## How This Could Be Solved Before the Witness Was Public

The first solver did not need to know the later spend witness. The 12 `asset_lock` output scripts were already public in the funding transaction, and each script commits to its storage slot. Since `asset_lock.simf` computes the spendable script hash from `nonce`, a solver can test nonce candidates offline and compare the resulting scriptPubKeys against funding vouts 0..11.

The likely route is:

1. Take the 12 public `asset_lock` scriptPubKeys from funding transaction vouts 0..11.
2. Take the BIP39 English word list. All words fit into 8 bytes.
3. For each word, build `nonce_bytes = word.as_bytes() || zero_padding_to_8_bytes`.
4. Interpret those 8 bytes as a big-endian `u64`.
5. Rebuild `AssetLockProgram` with the known `OWNER_PUBKEY`, set storage slot 0 to `24 zero bytes || nonce.to_be_bytes()`, and compute its scriptPubKey.
6. Match generated scriptPubKeys against the 12 funding outputs.
7. Read the matched words in funding vout order and validate the resulting BIP39 mnemonic against the OP_RETURN owner pubkey.

In pseudocode:

```text
for word in bip39_english_words:
    nonce = be_u64(word_bytes_padded_right_with_zeros_to_8)
    storage[0] = 0x000000000000000000000000000000000000000000000000 || nonce.to_be_bytes()
    script = asset_lock_script_pubkey(owner_pubkey, storage)
    if script in funding_asset_lock_scripts:
        record funding_vout -> word
```

This search is tiny: 2048 candidate words for 12 public outputs. It produces the same ordered mnemonic without relying on the later witness disclosure:

```text
hole art knife walnut language cool borrow board rival silk october boy
```

## Owner Key

Simplex derives the active signing key on Liquid mainnet as:

```text
m/84'/1776'/0'/0/0
```

Using the recovered mnemonic and empty BIP39 passphrase:

```text
owner private key:
476f8dcb2d92a8ac9d5962b02e68dc445553f98a56cdf24c71aa5a742c68bf5b

x-only pubkey:
e2d2636ee884d4e1137dfb15bdff1bc8df7c01812bc142c7323202237c696573
```

That x-only pubkey matches the OP_RETURN owner key in funding vout 13.

## Verification Script

```python
import json
import urllib.request

from bip_utils import Bip39MnemonicValidator, Bip39SeedGenerator, Bip32Slip10Secp256k1
from coincurve import PrivateKey

spend_txid = "d42f6bc30f4eac43fbe5dcd11552754307150c7654a4867a2019f31cbedf30d3"
owner = "e2d2636ee884d4e1137dfb15bdff1bc8df7c01812bc142c7323202237c696573"

tx = json.load(urllib.request.urlopen(f"https://blockstream.info/liquid/api/tx/{spend_txid}"))

words = []
for vin in tx["vin"][1:13]:
    witness0 = bytes.fromhex(vin["witness"][0])
    nonce = witness0[64:]
    words.append(nonce.rstrip(b"\x00").decode("ascii"))

mnemonic = " ".join(words)
assert Bip39MnemonicValidator().IsValid(mnemonic)

seed = Bip39SeedGenerator(mnemonic).Generate("")
ctx = Bip32Slip10Secp256k1.FromSeed(seed).DerivePath("m/84'/1776'/0'/0/0")
priv = ctx.PrivateKey().Raw().ToBytes()
xonly = PrivateKey(priv).public_key.format(compressed=False)[1:33].hex()

print(mnemonic)
print(priv.hex())
print(xonly)
assert xonly == owner
```

## Final Transaction Shape

The winning transaction spends:

```text
vin 0:  funding tx vout 12, the CTF reward program
vin 1..12: funding tx vout 0..11, the 12 asset_lock programs
```

and creates:

```text
vout 0: 12 units of auth asset 6e49cd6e...cc3b739
```

This satisfies `ctf.simf`, which only requires input 0 to be the reward contract and output 0 to contain all 12 auth tokens. The L-BTC reward is unconstrained by the covenant and is moved to the solver's confidential output.

## How the Reward Is Claimed

The original 0.01 L-BTC reward is not locked to the mnemonic's normal wallet address. It is locked to the CTF Taproot/Simplicity contract:

```text
aa52a138a0e193c8530e1195b201c7139de194decc0ff3bb01489adbe814095c:12
ex1pjfgf8zmw9tmmgy93zrpcsmyn8cskca045mn8vwd0pf6a24pdghpqc4635p
```

The recovered mnemonic gives the owner signing key, not direct key-path control over that contract UTXO. Importing the mnemonic into a normal wallet only gives the derived P2WPKH address:

```text
ex1qj65kznpqvjnu6uwy25n63cnwtghz2k9ner3ynm
```

To claim before it was spent, the solver had to build a Simplicity spend:

1. Create a `Signer` from the recovered mnemonic on Liquid mainnet.
2. Rebuild `CtfProgram` with the recovered `OWNER_PUBKEY` and auth asset id `6e49cd6e...cc3b739`.
3. Rebuild the 12 `AssetLockProgram`s. For each word, encode `word_bytes || zero_padding` as an 8-byte big-endian `u64`, then set storage slot 0 to `24 zero bytes || nonce.to_be_bytes()`.
4. Add the CTF reward UTXO as input 0. This is required because `ctf.simf` asserts `current_index() == 0`.
5. Add output 0 containing exactly 12 units of the auth asset. This satisfies the CTF covenant.
6. Add the 12 `asset_lock` UTXOs as inputs 1..12, each with its matching nonce witness.
7. Send the unconstrained L-BTC reward change to any address controlled by the solver, and pay the transaction fee.
8. Let the Simplex signer inject the Schnorr signatures for the CTF input and all 12 `asset_lock` inputs.

The real spend follows this pattern. It sends 12 auth units to output 0, pays a 389 sat fee, and moves the L-BTC reward into a solver-controlled confidential output.

## PR Review

PR #1 and PR #2 are test-harness solves, not the public-chain solve. Both create fresh local contracts and fresh auth assets, then sign with the test harness default signer. PR #2's claim that one `SIGHASH_ALL` signature authorizes every input is also misleading: the real spend contains one 64-byte Schnorr signature per program input, plus the 8-byte nonce for each `asset_lock`.
