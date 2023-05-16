#parsing a bitcoin transaction
from hashlib import sha256
import math
import sys



def get_tx_id(raw_tx):
    hash1 = sha256(raw_tx).digest()
    hash2 = sha256(hash1).digest()

    txid = hash2[::-1]
    return txid

##tx_hex = '0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'

tx_hex = '020000000001017e10f7735f4268f56421ea91830d9c20caca89d582d5822b7895a21a7d8e118b0000000000feffffff02e49d181e010000001976a914163f90c48cc8194a155fbfd1a76469ce92d10aec88aca048ed0b000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac0247304402206993ec9cb641f490e6402cce526e2910742dbaaebbe74c001f9ffd643e7781d8022015c0bdf32802c7bd9f5489f888677ecf6e11e3ced77920fdd8a02ecad6c70fc30121033902647da596b064d548c2a4d6282ba744596bae75fe84b94bda97ffafe98ffd65000000'
raw_tx = bytes.fromhex(tx_hex)
print(type(raw_tx))

hash1 = sha256(raw_tx).digest()
hash2 = sha256(hash1).digest()

print("Two rounds of SHA256 on the raw tx gives us: ", hash2.hex())
txid = hash2[::-1]
print("Reversing the bytes to little endian: ", txid.hex())

size = len(raw_tx)

weight = size*4

#vbytes round up

vsize = math.ceil(weight/4)

print(get_tx_id(raw_tx).hex())