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

## create address to spend to

## must be 32 byte (string in hex 64 length)
sender_privkey = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
sender_pubkey = privkey_to_pubkey(sender_privkey)
address_to_spend = pk_to_p2wpkh(sender_pubkey, network = "regtest")
print("sender's p2wpkh address: " + address_to_spend)

### helper function that sets up test environment
node = setup_testshell()
txid_to_spend, index_to_spend = fund_address(node, address_to_spend, 2.001)
print(f"txid: {txid_to_spend}, {index_to_spend}")

## we want to spend funds to bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw

## need to get the pubkey/script hash from address
## helper function b32.decode help with this. Takes human readable part(bcrt for regtest) and address as argurment
## returns witness version and witness program
## witness prgram is pubkey hash(20 bytes) or script hash(32 bytes)

# human readable part

receiver_address = 'bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw'
hrp = 'bcrt'
witver, witprog = b32.decode(hrp, receiver_address)

pubkey_hash = bytearray(witprog)
print("witness version: ", witver)
print("pubkey/script hash: ", pubkey_hash.hex())

## now we take the witnes program(pubkey_hash) and combine it with 20 to make the scriptpubkey
receiver_spk = bytes.fromhex("0014") + pubkey_hash


##create change address and script pubkey

# Note we have already defined a few variables we need to create our transaction:
# The input utxo txid and index: `txid_to_spend` and `index_to_spend`
# The input private key and public key: `sender_privkey` and `sender_pubkey`

# Set our outputs
# Create a new pubkey to use as a change output.
change_privkey = bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222")
change_pubkey = privkey_to_pubkey(change_privkey)

# Determine our output scriptPubkeys and amounts (in satoshis)
output1_value_sat = int(float("1.5") * 100000000)
output1_spk = receiver_spk
output2_value_sat = int(float("0.5") * 100000000)
output2_spk = bytes.fromhex("0014") + hash160(change_pubkey)

## create unsigned transaction in format from https://en.bitcoin.it/wiki/Protocol_documentation#tx
# VERSION
# version '2' indicates that we may use relative timelocks (BIP68)
version = bytes.fromhex("0200 0000")

# MARKER (new to segwit)
marker = bytes.fromhex("00")

# FLAG (new to segwit)
flag = bytes.fromhex("01")

# INPUTS
# We have just 1 input
input_count = bytes.fromhex("01")

# Convert txid and index to bytes (little endian)
txid = (bytes.fromhex(txid_to_spend))[::-1]
index = index_to_spend.to_bytes(4, byteorder="little", signed=False)

# For the unsigned transaction we use an empty scriptSig
scriptsig = bytes.fromhex("")

# use 0xffffffff unless you are using OP_CHECKSEQUENCEVERIFY, locktime, or rbf
sequence = bytes.fromhex("ffff ffff")

inputs = (
    txid
    + index
    + varint_len(scriptsig)
    + scriptsig
    + sequence
)

# OUTPUTS
# 0x02 for out two outputs
output_count = bytes.fromhex("02")

# OUTPUT 1 
output1_value = output1_value_sat.to_bytes(8, byteorder="little", signed=True)
# 'output1_spk' already defined at the start of the script

# OUTPUT 2
output2_value = output2_value_sat.to_bytes(8, byteorder="little", signed=True)
# 'output2_spk' already defined at the start of the script

outputs = (
    output1_value
    + varint_len(output1_spk)
    + output1_spk
    + output2_value
    + varint_len(output2_spk)
    + output2_spk
)

# LOCKTIME
locktime = bytes.fromhex("0000 0000")

unsigned_tx = (
    version
    + input_count
    + inputs
    + output_count
    + outputs
    + locktime
)
print("unsigned_tx: ", unsigned_tx.hex())
decoded = node.decoderawtransaction(unsigned_tx.hex())
print(json.dumps(decoded, indent=2, default=str))

## segwit transaction have new signing scheme based on BIP143
## https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki

'''  Double SHA256 of the serialization of:
     1. nVersion of the transaction (4-byte little endian)
     2. hashPrevouts (32-byte hash)
     3. hashSequence (32-byte hash)
     4. outpoint (32-byte hash + 4-byte little endian) 
     5. scriptCode of the input (serialized as scripts inside CTxOuts)
     6. value of the output spent by this input (8-byte little endian)
     7. nSequence of the input (4-byte little endian)
     8. hashOutputs (32-byte hash)
     9. nLocktime of the transaction (4-byte little endian)
    10. sighash type of the signature (4-byte little endian)
'''

pk_hash = hash160(sender_pubkey)
scriptcode = bytes.fromhex("76a914" + pk_hash.hex() + "88ac")

input_amount_sat = int(2.001 * 100_000_000)
value = input_amount_sat.to_bytes(8, byteorder="little", signed=False)

hashPrevOuts = hash256(txid + index)
hashSequence = hash256(sequence)
hashOutputs = hash256(outputs)
sighash_type = bytes.fromhex("0100 0000") # SIGHASH_ALL

tx_digest_preimage = (
    version
    + hashPrevOuts
    + hashSequence
    + txid
    + index
    + varint_len(scriptcode)
    + scriptcode
    + value
    + sequence
    + hashOutputs
    + locktime
    + sighash_type
)
print(tx_digest_preimage.hex())

## double hash it per bip143

sighash = hash256(tx_digest_preimage)
# Sign the sigHash with the input private key
signing_key = ecdsa.SigningKey.from_string(sender_privkey, curve=ecdsa.SECP256k1) 
signature = signing_key.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der_canonize)

# Append SIGHASH_ALL to the signature
signature = signature + bytes.fromhex("01")

# Witness field
witness = (
    # indicate the number of stack items for the txin
    # 2 items for signature and pubkey
    bytes.fromhex("02")
    + pushbytes(signature)
    + pushbytes(sender_pubkey)
)

# tx_in with our new sigScript containing the signature we just created
inputs_signed = (
    txid
    + index
    + varint_len(scriptsig)
    + scriptsig
    + sequence
)

# the final signed transaction
signed_tx = (
    version
    + marker
    + flag
    + input_count
    + inputs_signed
    + output_count
    + outputs
    + witness
    + locktime
)

print("signed transaction: ",signed_tx.hex())

##broadcast transaction

new_tx_txid = node.sendrawtransaction(signed_tx.hex())
# result = node.testmempoolaccept(rawtxs=[signed_tx.hex()])
print(new_tx_txid)

print("receiver's p2pkh address: " + receiver_address)
change_p2pkh_addr = pk_to_p2pkh(change_pubkey, network = "regtest")
print("sender's change p2pkh address: " + change_p2pkh_addr)

decoded = node.decoderawtransaction(signed_tx.hex())
print(json.dumps(decoded, indent=2, default=str))

'''
1. What fields to the transaction are introduced in segwit v0 transactions compared to legacy transactions?
marker flag and witness
2. When spending from a segwit v0 input, the sighash algorithm includes the input amount. For legacy outputs, the sighash does not include the amount. What advantage does this have for offline signers?
Signers like hardware devices do not have to get info from outside sources to verify the amount of transactions are correct
3.  If you compare the transaction we created here to the transaction in the P2PKH notebook, you'll see it's roughly the same size in terms of the total number of bytes. So why are segwit transactions cheaper in terms of mining fees?
Segwit introduces block weight which discoutn the witness data by 75 percennt when paying transaction fees
'''