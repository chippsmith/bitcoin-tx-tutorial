import sys

path_to_bitcoin_functional_test = "/Users/chrissmith/bitcoin/test/functional"
path_to_bitcoin_tx_tutorial = "/Users/chrissmith/Projects/bitcoin-tx-tutorial"

# Add the functional test framework to our PATH
sys.path.insert(0, path_to_bitcoin_functional_test)
from test_framework.test_shell import TestShell

# Add the bitcoin-tx-tutorial functions to our PATH
sys.path.insert(0, path_to_bitcoin_tx_tutorial)
from functions import *
from functions.bip_0340_reference import taproot_tweak_pubkey


'''
Taptree binary tree commitments

Committing multiple tapscripts requires a commitment structure resembling merkle tree construction.

The TapTree is different than the header merkle tree in the following ways:

    Tapleaves can be located at different heights.
    Ordering of TapLeaves is determined lexicograpically.
    Location of nodes are tagged (No ambiguity of node type).

Internal nodes are called tapbranches, and are also computed with the tagged_hash("Tag", input_data) function.

Tagged hashes are particularly useful when building a taptree commitment. They prevent node height ambiguity currently found 
in the transaction merkle tree, which allows an attacker to create a node which can be reinterpreted as either a leaf or internal node.
Tagged hashes ensure that a tapleaf cannot be misinterpreted as an internal node and vice versa.
'''

### define tagged hash

# Tagged Hashes
# the 'tag' depends on where the tagged hash is being used e.g. 'TapTweak', 'TapBranch', TapScript'
def tagged_hash(tag, msg):
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + msg)


TAPSCRIPT_VER = bytes([0xc0])  # This is currently the only tapscript version. In future there may be others.
internal_privkey = bytes.fromhex("83a5f1039118fbb4276cac2db41d236c1c1790d97d955c228fa3bde439fbec2a")
internal_pubkey = tr.pubkey_gen(internal_privkey)

# Derive three private/public (x-only) key pairs
privkeyA = bytes.fromhex("1059bf26660804ced9a3286a16497d7e70692d14dc04e1220c2dbef3667b74f7")
pubkeyA = tr.pubkey_gen(privkeyA)
privkeyB = bytes.fromhex("2b22bf11ab862a35f16301c0afc7afe60f66d31fc29645f79c2ab43655e65d33")
pubkeyB = tr.pubkey_gen(privkeyB)
privkeyC = bytes.fromhex("7f8b28e51da049bf63e31d3a3261579c0f5c1fc8058c65a79482814e5061f9f6")
pubkeyC = tr.pubkey_gen(privkeyC)

# Create corresponding pubkey scripts
scriptA = b"\x20" + pubkeyA + b"\xac"
scriptB = b"\x20" + pubkeyB + b"\xac"
scriptC = b"\x20" + pubkeyC + b"\xac"

# Method: Returns tapbranch hash. Child hashes are lexographically sorted and then concatenated.
# l: tagged hash of left child
# r: tagged hash of right child
def tapbranch_hash(l, r):
    return tagged_hash("TapBranch", b''.join(sorted([l,r])))

# 1) Compute TapLeaves A, B and C.
# Method: pushbytes(data) is a function which adds compactsize to input data.
# This addes three leafs to the tap tree
# This can be spent by the witness data for a script plus the script plus the merkle proof the script was in the tree
hash_inputA =  TAPSCRIPT_VER + pushbytes(scriptA)
hash_inputB =  TAPSCRIPT_VER + pushbytes(scriptB)
hash_inputC =  TAPSCRIPT_VER + pushbytes(scriptC)
taggedhash_leafA =  tagged_hash("TapLeaf", hash_inputA)
taggedhash_leafB =  tagged_hash("TapLeaf", hash_inputB)
taggedhash_leafC =  tagged_hash("TapLeaf", hash_inputC)

# 2) Compute Internal node TapBranch AB.
internal_nodeAB = tapbranch_hash(taggedhash_leafA, taggedhash_leafB)

# 3) Compute TapTweak.
rootABC =  tapbranch_hash(internal_nodeAB, taggedhash_leafC)
taptweak =  tagged_hash("TapTweak", internal_pubkey + rootABC)

# 4) Derive the bech32m address.
negated, taproot_pubkey = taproot_tweak_pubkey(internal_pubkey, rootABC)
print("TapTweak:", taptweak.hex())
spk = bytes.fromhex("5120") + taproot_pubkey
bech32m_address = spk_to_bech32(spk, 'regtest')
print('Bech32m address:', bech32m_address)