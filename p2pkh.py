path_to_bitcoin_functional_test = "/Users/chrissmith/bitcoin/test/functional"
path_to_bitcoin_tx_tutorial = "/Users/chrissmith/Projects/bitcoin-tx-tutorial"
import sys

# Add the functional test framework to our PATH
sys.path.insert(0, path_to_bitcoin_functional_test)
from test_framework.test_shell import TestShell

# Add the bitcoin-tx-tutorial functions to our PATH
sys.path.insert(0, path_to_bitcoin_tx_tutorial)
from functions import hash160, privkey_to_pubkey, pk_to_p2pkh, decode_base58, varint_len, hash256, ecdsa, pushbytes

import json

# Setup our regtest environment
test = TestShell().setup(
    num_nodes=1, 
    setup_clean_chain=True
)

node = test.nodes[0]

# Create a new wallet and address to send mining rewards so we can fund our transactions
node.createwallet(wallet_name='mywallet')
address = node.getnewaddress()

# Generate 101 blocks so that the first block subsidy reaches maturity
result = node.generatetoaddress(nblocks=101, address=address, invalid_call=False)

# Check that we were able to mine 101 blocks
assert(node.getblockcount() == 101)

sender_privkey = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
sender_pubkey = privkey_to_pubkey(sender_privkey)
sender_p2pkh_addr = pk_to_p2pkh(sender_pubkey, network = "regtest")
print("sender's p2pkh address: " + sender_p2pkh_addr)

txid_to_spend = node.sendtoaddress(sender_p2pkh_addr, 2.001)
print(txid_to_spend)

raw_tx = node.getrawtransaction(txid_to_spend)
decoded = node.decoderawtransaction(raw_tx)
print(json.dumps(decoded, indent=2, default=str))

'Find which output index the btc was sent to'

if decoded["vout"][0]["scriptPubKey"]["address"] == sender_p2pkh_addr:
    index_to_spend = 0
elif decoded["vout"][1]["scriptPubKey"]["address"] == sender_p2pkh_addr:
    index_to_spend = 1
else:
    raise Exception("couldn't find output")


print("index to spend from: " + str(index_to_spend))

node.generatetoaddress(1, address, invalid_call=False)

receiver_address = 'mkxwE7XtVYJKepoD2hbHnDjftuMQ1k6deE'
receiver_address_decoded = decode_base58(receiver_address)
# TODO: create a function in the address chapter to validate and parse addresses and use here

prefix = receiver_address_decoded[0]  
pubkey_hash = receiver_address_decoded[1:-4] 
checksum = receiver_address_decoded[-4:]
print(hex(prefix))
print(pubkey_hash.hex())
print(checksum.hex())

receiver_spk = bytes.fromhex("76a914") + pubkey_hash + bytes.fromhex("88ac")

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
output2_spk = bytes.fromhex("76a914") + hash160(change_pubkey) + bytes.fromhex("88ac")

### creating the bitcoin transaction from scratch

# We have all the info we need we just need to put it in the right order per https://en.bitcoin.it/wiki/Protocol_documentation#tx
# 4 byte version, varint number txs, list of txs, varint tx_out, tx_witness, 4 bytes 4 bytes locktime
# txin is txid, index, len(scirptsig), scriptsig, sequence
# txout is len scriptpubkey followed by scriptpubkey followed 8 bytes amount 


version = bytes.fromhex("0200 0000")
input_count = bytes.fromhex('01')
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

## Decode unsigned transaction
decoded = node.decoderawtransaction(unsigned_tx.hex())
print(json.dumps(decoded, indent=2, default=str))


## now we need to prepare the transaction for signing
## we need to replace the empty scriptSig with the input scriptpubkey

pk_hash = hash160(sender_pubkey)
input_spk = bytes.fromhex("76a914" + pk_hash.hex() + "88ac")

##new inputs to sign
inputs = (
    txid
    + index
    + varint_len(input_spk)
    + input_spk # replace the empty scriptSig with the input scriptPubkey
    + sequence
)

# update the tx hex to sign with the new inputs
# tx hex to sign
tx_to_sign = (
    version
    + input_count
    + inputs
    + output_count
    + outputs
    + locktime
)

## before we sign we need to append the sighash all flag

sighash_flag = bytes.fromhex("0100 0000") # SIGHASH_ALL
sighash_preimage = tx_to_sign + sighash_flag

# we now has the preimage to get the sighash to sign
sighash = hash256(sighash_preimage)

# Sign the sigHash with the input private key
signing_key = ecdsa.SigningKey.from_string(sender_privkey, curve=ecdsa.SECP256k1) 
signature = signing_key.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der_canonize)


# Append SIGHASH_ALL to the signature
signature = signature + bytes.fromhex("01")

# Signature
sig_script_signed = (
    pushbytes(signature)
    + pushbytes(sender_pubkey)
)

# tx_in with our new sigScript containing the signature we just created
inputs_signed = (
    txid
    + index
    + varint_len(sig_script_signed)
    + sig_script_signed
    + sequence
)

# the final signed transaction
signed_tx = (
    version
    + input_count
    + inputs_signed
    + output_count
    + outputs
    + locktime
)

print("signed transaction: ",signed_tx.hex())

##broadcast tx on regtest

new_tx_txid = node.sendrawtransaction(signed_tx.hex())
# new_tx_txid = node.testmempoolaccept(signed_tx.hex())

print(new_tx_txid)


print("receiver's p2pkh address: " + receiver_address)
change_p2pkh_addr = pk_to_p2pkh(change_pubkey, network = "regtest")
print("sender's change p2pkh address: " + change_p2pkh_addr)

ecoded = node.decoderawtransaction(signed_tx.hex())
print(json.dumps(decoded, indent=2, default=str))

test.shutdown()


'''
Quiz
1.How is the transaction ID calculated? double sha256 of the raw transaction. output is in little endian
2. Which field of a transaction contains the signature(s)? script sig
3. Bitcoin ECDSA signatures are vulnerable to third party malleation. As a result, it is possible for a third party to alter the transaction ID. If Alice is broadcasting a transaction to Bob, how might a third party manage to change the transaction ID using only publicly available information?
There are ways to change the signature by adding bytes or using the oppoiste value on the ecdsa curve to 
produce a valid signautre but changing the tx id.  inputs and outputs and amount remain the same
4.  This causes problems for transactors on the network who may need to prove they sent a transaction.
    It also causes problem for second layers like the lightning network who rely on the funding transaction
    to have a non malleable txid so they can construct a commmitment transcation based on it.
'''