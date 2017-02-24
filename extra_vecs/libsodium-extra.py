import pysodium

def test(msg, aad, nonce, key):
    ct = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt(msg, aad, nonce, key)
    ct, tag = ct[:len(msg)], ct[len(msg):]

    print """
  vector("%s",
         "%s",
         "%s",
         "%s",
         "%s",
         "%s");""" % (key.encode('hex'), nonce.encode('hex'), aad.encode('hex'), msg.encode('hex'), ct.encode('hex'), tag.encode('hex'))

key = 'key.' * 8
nonce = 'nonce.' * 2
msg = 'message' * 5
aad = 'aad' * 12

for msgl in range(32):
    test(msg[:msgl], aad, nonce, key)

for aadl in range(32):
    test(msg, aad[:aadl], nonce, key)
