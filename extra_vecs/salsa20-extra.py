import salsa20

key = ('secretkey'*4)[:32]
nonce = ('nonce'*2)[:8]
keystream = salsa20.Salsa20_keystream(128, nonce, key)

print """vector("%s", "%s", "%s");""" % (key.encode('hex'), nonce.encode('hex'), keystream.encode('hex'))
