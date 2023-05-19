import sys
import json

path_to_bitcoin_functional_test = "/Users/chrissmith/bitcoin/test/functional"
path_to_bitcoin_tx_tutorial = "/Users/chrissmith/Projects/bitcoin-tx-tutorial"

# Add the functional test framework to our PATH
sys.path.insert(0, path_to_bitcoin_functional_test)
from test_framework.test_shell import TestShell

# Add the bitcoin-tx-tutorial functions to our PATH
sys.path.insert(0, path_to_bitcoin_tx_tutorial)
from functions import *


def pubkey_gen(seckey: bytes) -> bytes:
    d0 = tr.int_from_bytes(seckey)
    if not (1 <= d0 <= tr.n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = tr.point_mul(tr.G, d0)
    assert P is not None
    return tr.bytes_from_point(P)



# Basic example of creating a private key and signing and verifying a message with schnorr
# Generate a key pair
privkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
pubkey = pubkey_gen(privkey)
print(f"Private key: {privkey.hex()}\nPublic key: {pubkey.hex()}\n")

msg = sha256(b'msg')
aux_rand = bytes(32) # auxiliary random data
sig = tr.schnorr_sign(msg, privkey, aux_rand)
print(f"Signature: {sig.hex()}\n")

assert(tr.schnorr_verify(msg, pubkey, sig))
print("Success!")

# Example of tweaking the pubkey(secure commitment because P appears inside and outside the hash )

# Generate a key pair
privkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000004")

# Set the private key to an integer for elliptic curve operations
d0 = int.from_bytes(privkey, byteorder="big")

# Compute pubkey, but if it's odd we'll need to negate the privkey
P0 = tr.point_mul(tr.G, d0)

# We need this step to make sure we negate pubkeys with odd y-coordinates
d = d0 if tr.has_even_y(P0) else tr.SECP256K1_ORDER - d0

# Generate the public key. Note that we don't use the function pubkey_gen as
# we want the full point (not just the x-coordinate)
P = tr.point_mul(tr.G, d)

# The contract data we want to commit to
contract = "Alice agrees to pay 10 BTC to Bob"

# The tweak will commit to the contract data as well as the original pubkey to protect
# against the vulnerability mentioned in the previous part
tweak_int = tr.int_from_bytes(tr.tagged_hash("TapTweak", tr.bytes_from_int(tr.x(P)) + contract.encode('utf-8')))

# Generate the tweak point
T = tr.point_mul(tr.G, tweak_int)

# Generate the tweaked pubkey by adding the tweak point and pubkey
TW = tr.point_add(P, T)

# Extract the x-coordinate for our final tweaked x-only pubkey
tweaked_x_only_pubkey = tr.bytes_from_int(tr.x(TW))