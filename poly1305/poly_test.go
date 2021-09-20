package poly1305

import (
	"testing"

	"ChaCha-Go/chacha"
	"ChaCha-Go/shared"
)

func Test_generateKey(t *testing.T) {
	key := []byte{
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	}
	nonce := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	}

	cc := chacha.New(key, nonce, uint32(0))
	state := cc.InitState(0)

	expectedStateWithKeySetup := []uint32{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0x83828180, 0x87868584, 0x8b8a8988, 0x8f8e8d8c,
		0x93929190, 0x97969594, 0x9b9a9998, 0x9f9e9d9c,
		0x00000000, 0x00000000, 0x03020100, 0x07060504,
	}
	if !shared.AreWordSlicesEqual(state, expectedStateWithKeySetup) {
		t.Error("invalid state with key setup")
		return
	}

	expectedStateAfter20Rounds := []uint32{
		0x8ba0d58a, 0xcc815f90, 0x27405081, 0x7194b24a,
		0x37b633a8, 0xa50dfde3, 0xe2b8db08, 0x46a6d1fd,
		0x7da03782, 0x9183a233, 0x148ad271, 0xb46773d1,
		0x3cc1875a, 0x8607def1, 0xca5c3086, 0x7085eb87,
	}
	stateAfter20Rounds := cc.Block(state)
	if !shared.AreWordSlicesEqual(stateAfter20Rounds, expectedStateAfter20Rounds) {
		t.Error("invalid state after 20 rounds")
	}

	expectedMACKey := []byte{
		0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71,
		0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46,
	}
	macKey := chacha.Serialize(stateAfter20Rounds)[:32]
	if !shared.AreByteSlicesEqual(macKey, expectedMACKey) {
		t.Error("something is wrong with serialization")
	}

}
