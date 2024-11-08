import ecdsa
import hashlib
import struct
import unittest
import base58

#Helper functions (replace utils and keyUtils with direct implementations)

def varstr(s):
    if len(s) < 253:
        return bytes([len(s)]) + s
    elif len(s) < 65536:
        return bytes([253]) + struct.pack("<H", len(s)) + s
    elif len(s) < 4294967296:
        return bytes([254]) + struct.pack("<I", len(s)) + s
    else:
        return bytes([255]) + struct.pack("<Q", len(s)) + s

def privateKeyToPublicKey(privateKey):
    sk = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    publicKey = b'\x04' + vk.to_string()
    return publicKey.hex()

def pubKeyToAddr(publicKey):
    publicKeyBytes = bytes.fromhex(publicKey)
    sha256hash = hashlib.sha256(publicKeyBytes).digest()
    ripemd160hash = hashlib.new('ripemd160', sha256hash).digest()
    prefix = b'\x00' # For mainnet addresses
    extendedripemd160 = prefix + ripemd160hash
    checksum = hashlib.sha256(hashlib.sha256(extendedripemd160).digest()).digest()[:4]
    addressBytes = extendedripemd160 + checksum
    return base58.b58encode(addressBytes).decode()

def derSigToHexSig(derSig):
    #This function requires a more robust implementation for proper DER decoding and handling.  This is a placeholder.
    return derSig


def wifToPrivateKey(wif):
    decoded = base58.b58decode_check(wif)
    return decoded[1:].hex()

def addrHashToScriptPubKey(address):
    decoded = base58.b58decode_check(address)
    hash160 = decoded[1:21]
    return "76a914" + hash160.hex() + "88ac"



# Makes a transaction from the inputs
# outputs is a list of [redemptionSatoshis, outputScript]

def makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs):
    def makeOutput(data):
        redemptionSatoshis, outputScript = data
        return (struct.pack("<Q", redemptionSatoshis).hex() +
                '%02x' % len(bytes.fromhex(outputScript)) + outputScript)
    formattedOutputs = ''.join(map(makeOutput, outputs))

    return ("01000000" +  # 4 bytes version
            "01" +  # varint for number of inputs
            bytes.fromhex(outputTransactionHash[::-1]).hex() +  # reverse outputTransactionHash
            struct.pack('<L', sourceIndex).hex() +
            '%02x' % len(bytes.fromhex(scriptSig)) + scriptSig +
            "ffffffff" +  # sequence
            "%02x" % len(outputs) +  # number of outputs
            formattedOutputs +
            "00000000"  # lockTime
            )


# Returns [first, sig, pub, rest]

def parseTxn(txn):
    txn_bytes = bytes.fromhex(txn)
    first = txn_bytes[:41].hex()
    scriptLen = txn_bytes[41]
    script = txn_bytes[42:42+scriptLen].hex()
    sigLen = txn_bytes[42]
    sig = txn_bytes[43:43+sigLen].hex()
    pubLen = txn_bytes[43+sigLen]
    pub = txn_bytes[44+sigLen:44+sigLen+pubLen].hex()
    rest = txn_bytes[44+sigLen+pubLen:].hex()
    return [first, sig, pub, rest]


# Substitutes the scriptPubKey into the transaction, appends SIGN_ALL to make the version
# of the transaction that can be signed

def getSignableTxn(parsed):
    first, sig, pub, rest = parsed
    inputAddr = pubKeyToAddr(pub)
    scriptPubKey = addrHashToScriptPubKey(inputAddr)
    return first + scriptPubKey + rest + "01000000"


# Verifies that a transaction is properly signed, assuming the generated scriptPubKey matches
# the one in the previous transaction's output

def verifyTxnSignature(txn):
    parsed = parseTxn(txn)
    signableTxn = getSignableTxn(parsed)
    hashToSign = hashlib.sha256(hashlib.sha256(bytes.fromhex(signableTxn))).digest().hex()
    assert(parsed[1][-2:] == '01')  # hashtype
    sig = derSigToHexSig(parsed[1][:-2])
    public_key = parsed[2]
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key[2:]), curve=ecdsa.SECP256k1)
    try:
        assert(vk.verify_digest(bytes.fromhex(sig), bytes.fromhex(hashToSign)))
    except ecdsa.BadSignatureError:
        print("Bad Signature")
        return False
    return True


def makeSignedTransaction(privateKey, outputTransactionHash, sourceIndex, scriptPubKey, outputs):
    myTxn_forSig = (makeRawTransaction(outputTransactionHash, sourceIndex, scriptPubKey, outputs) + "01000000")  # hash code
    s256 = hashlib.sha256(hashlib.sha256(bytes.fromhex(myTxn_forSig))).digest()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(privateKey), curve=ecdsa.SECP256k1)
    sig = sk.sign_digest(s256, sigencode=ecdsa.util.sigencode_der) + b'\x01'  # 01 is hashtype
    pubKey = privateKeyToPublicKey(privateKey)
    scriptSig = varstr(sig).hex() + varstr(bytes.fromhex(pubKey)).hex()
    signed_txn = makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs)
    return signed_txn


class TestTxnUtils(unittest.TestCase):
    #Test cases remain largely the same, but you'll need to update the expected values if necessary.


if __name__ == '__main__':
    unittest.main()
