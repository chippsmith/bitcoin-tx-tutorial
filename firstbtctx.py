#parsing a bitcoin transaction
from hashlib import sha256
import math


tx_hex = '0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7 aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'
raw_tx = bytes.fromhex(tx_hex)

hash1 = sha256(raw_tx).digest()
hash2 = sha256(hash1).digest()

print("Two rounds of SHA256 on the raw tx gives us: ", hash2.hex())
txid = hash2[::-1]
print("Reversing the bytes to little endian: ", txid.hex())

size = len(raw_tx)

weight = size*4

#vbytes round up

vsize = math.ceil(weight/4)