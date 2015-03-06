

from Crypto import PublicKey
from Crypto.Hash import SHA
from Crypto.Util import number
from Crypto.Signature import PKCS1_v1_5

import binascii, struct, array
import Crypto.PublicKey.RSA
impl = Crypto.PublicKey.RSA.RSAImplementation()

misc_notes_deleteme = """
kevinh@kevin-think:~/development/drone/PX4Firmware$ Tools/px_uploader.py --readonly --port /dev/ttyACM0  bob
Found board 9,0 bootloader rev 4 on /dev/ttyACM0
50583400 00ac2600 00100000 00ffffff ffffffff ffffffff ffffffff ffffffff

3296c911 56c6a2cd 9d472bd7 68e74ad9 c731d43b 9180a994 f9b92751 7e41425a
5207fe58 42dd9bcd 27f20777 59ca9772 92334e8c 366969f3 797efaaa 6940ad00
c0190f18 5410e5fd 13dce5b3 7b8f8030 ab84e1fa 1c026088 eb1ee4b2 24fb662b
a800a811 0a956c55 fe43698f a584e9a1 d7f8b104 95e3460c 1de681c0 c7b89875

ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff
type: PX4
idtype: =00
vid: 000026ac
pid: 00000010
coa: MpbJEVbGos2dRyvXaOdK2ccx1DuRgKmU+bknUX5BQlpSB/5YQt2bzSfyB3dZypdykjNOjDZpafN5fvqqaUCtAMAZDxhUEOX9E9zls3uPgDCrhOH6HAJgiOse5LIk+2YrqACoEQqVbFX+Q2mPpYTpodf4sQSV40YMHeaBwMe4mHU=

sn: 002700303133470539343031
"""

coaBase64 = "MpbJEVbGos2dRyvXaOdK2ccx1DuRgKmU+bknUX5BQlpSB/5YQt2bzSfyB3dZypdykjNOjDZpafN5fvqqaUCtAMAZDxhUEOX9E9zls3uPgDCrhOH6HAJgiOse5LIk+2YrqACoEQqVbFX+Q2mPpYTpodf4sQSV40YMHeaBwMe4mHU="
coaBytes = binascii.a2b_base64(coaBase64)
print 'coa', ''.join('{:02x}'.format(ord(x)) for x in coaBytes)

# A 12 byte serial number (though the endianness is different when stored in the C code - see px_uploader.py)
serialStr = "002700303133470539343031"
#serialStr = "300027000547333131303439" # Is the endianness swapped?
serialSplit = [serialStr[i:i+2] for i in range(0, len(serialStr), 2)]
print "nums", serialSplit
serialNums = map(lambda b: int(b, 16), serialSplit)
serialNums.extend([ 0,0,0,0,0,0,0,0]) # pad to 20 bytes
print "asarray", serialNums
serialNum = array.array('B', serialNums).tostring() # FIXME - need to reverse? [::-1]
print 'asstr', ' '.join('{:02x}'.format(ord(x)) for x in serialNum)

with open('3dr_pub.pem') as f:
   pubKey = f.read()
print "pubkey len", len(pubKey)

with open('3dr_priv.pem') as f:
   prvKeyData = f.read()

hash = SHA.new(serialNum)

prvKey = PublicKey.RSA.importKey(prvKeyData)
#pub = prvKey.publickey()
pub = PublicKey.RSA.importKey(pubKey)

#longSignature = number.bytes_to_long(serialNum)
#print "long", longSignature
# print 'VERIFY:', pub.verify(hash, (longSignature, None))

signer = PKCS1_v1_5.new(prvKey)
myNewCOA = SHA.new(serialNum)
mySign = signer.sign(myNewCOA)
print "mysign len", len(mySign)

# FIXME - the following fails to parse a coa from the px4 on my desk
verifier = PKCS1_v1_5.new(pub)
print 'VERIFY mine:', verifier.verify(hash, mySign)
print 'VERIFY theirs:', verifier.verify(hash, coaBytes)
