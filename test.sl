(def check-aes (key pt ct)
	(+
		(assert (=
			ct
			(aes-encrypt key pt)))
		(assert (=
			pt
			(aes-decrypt key ct)))
	)
)

(check-aes
	[000102030405060708090a0b0c0d0e0f]
	[00112233445566778899aabbccddeeff]
	[69c4e0d86a7b0430d8cdb78070b4c55a]
)
(check-aes
	[000102030405060708090a0b0c0d0e0f1011121314151617]
	[00112233445566778899aabbccddeeff]
	[dda97ca4864cdfe06eaf70a0ec0d7191]
)
(check-aes
	[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]
	[00112233445566778899aabbccddeeff]
	[8ea2b7ca516745bfeafc49904b496089]
)

(check-aes
	[2b7e151628aed2a6abf7158809cf4f3c]
	[6bc1bee22e409f96e93d7e117393172a]
	[3ad77bb40d7a3660a89ecaf32466ef97]
)
(check-aes
	[2b7e151628aed2a6abf7158809cf4f3c]
	[ae2d8a571e03ac9c9eb76fac45af8e51]
	[f5d3d58503b9699de785895a96fdbaaf]
)
(check-aes
	[2b7e151628aed2a6abf7158809cf4f3c]
	[30c81c46a35ce411e5fbc1191a0a52ef]
	[43b1cd7f598ece23881b00e3ed030688]
)
(check-aes
	[2b7e151628aed2a6abf7158809cf4f3c]
	[f69f2445df4f9b17ad2b417be66c3710]
	[7b0c785e27e8ad3f8223207104725dd4]
)

(check-aes
	[8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b]
	[6bc1bee22e409f96e93d7e117393172a]
	[bd334f1d6e45f25ff712a214571fa5cc]
)
(check-aes
	[8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b]
	[ae2d8a571e03ac9c9eb76fac45af8e51]
	[974104846d0ad3ad7734ecb3ecee4eef]
)
(check-aes
	[8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b]
	[30c81c46a35ce411e5fbc1191a0a52ef]
	[ef7afd2270e2e60adce0ba2face6444e]
)
(check-aes
	[8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b]
	[f69f2445df4f9b17ad2b417be66c3710]
	[9a4b41ba738d6c72fb16691603c18e0e]
)

(check-aes
	[603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4]
	[6bc1bee22e409f96e93d7e117393172a]
	[f3eed1bdb5d2a03c064b5a7e3db181f8]
)
(check-aes
	[603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4]
	[ae2d8a571e03ac9c9eb76fac45af8e51]
	[591ccb10d410ed26dc5ba74a31362870]
)
(check-aes
	[603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4]
	[30c81c46a35ce411e5fbc1191a0a52ef]
	[b6ed21b99ca6f4f9f153e7b1beafed1d]
)
(check-aes
	[603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4]
	[f69f2445df4f9b17ad2b417be66c3710]
	[23304b7a39f9f3ff067d8d8f9e24ecc7]
)

(assert (=
	(sha224 (bytes "abc"))
	[23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7])
)

(assert (=
	(sha256 (bytes "abc"))
	[ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad])
)

(assert (=
	(sha256 (bytes "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
	[248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1])
)

(assert (=
	(sha256 (* (bytes "a") 1000000))
	[cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0])
)

(assert (=
	(sha256 (bytes "The quick brown fox jumps over the lazy dog"))
	[d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592])
)

(assert (=
	(sha256 (bytes "The quick brown fox jumps over the lazy cog"))
	[e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be])
)

(assert (=
	(sha224 [])
	[d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f])
)

(assert (=
	(sha256 [])
	[e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855])
)

(puts success)
