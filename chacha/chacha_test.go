/*
Package chacha implements ChaCha20 algorithm

MIT License

Copyright (c) 2021 Piotr Pszczółkowski

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package chacha

import (
	"testing"

	"ChaCha-Go/shared"
)

func Test_rorl32(t *testing.T) {
	value := uint32(0x7998bfda)
	shift := 7
	expected := uint32(0xcc5fed3c)

	result := rotl32(value, shift)
	if result != expected {
		t.Error("rotl32 not works")
	}
}

func Test_quarterRound(t *testing.T) {
	a := uint32(0x11111111)
	b := uint32(0x01020304)
	c := uint32(0x9b8d6f43)
	d := uint32(0x01234567)

	aExpectedAfter := uint32(0xea2a92f4)
	bExpectedAfter := uint32(0xcb1cf8ce)
	cExpectedAfter := uint32(0x4581472e)
	dExpectedAfter := uint32(0x5881c4bb)

	aAfter, bAfter, cAfter, dAfter := quarterRound(a, b, c, d)
	if aAfter == aExpectedAfter && bAfter == bExpectedAfter && cAfter == cExpectedAfter && dAfter == dExpectedAfter {
		return
	}
	t.Error("quarter round don't works")
}

func Test_quarterRoundOnState(t *testing.T) {
	state := []uint32{
		0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
		0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
		0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
		0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
	}
	stateExpectedAfter := []uint32{
		0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
		0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
		0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
		0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
	}

	quarterRoundOnState(state, 2, 7, 8, 13)
	for i, v := range state {
		if v != stateExpectedAfter[i] {
			t.Error("innerBlock don't work")
		}
	}
}

func Test_initState(t *testing.T) {
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	nonce := []byte{
		0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00,
	}
	blockCount := uint32(1)

	cc := New(key, nonce, uint32(0))

	expectedStateWithKeySetup := []uint32{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
		0x00000001, 0x09000000, 0x4a000000, 0x00000000,
	}
	state := cc.InitState(blockCount)
	if !shared.AreWordSlicesEqual(state, expectedStateWithKeySetup) {
		t.Error("invalid state with key setup")
		return
	}

	expectedStateAfter20Rounds := []uint32{
		0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
		0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
		0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
		0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
	}
	stateAfter20Rounds := Block(state)
	if !shared.AreWordSlicesEqual(stateAfter20Rounds, expectedStateAfter20Rounds) {
		t.Error("invalid state after 20 rounds")
	}

	expectedSerializedState := []byte{
		0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
		0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
		0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
		0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
		0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
		0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
		0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
		0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
	}
	serializedState := Serialize(stateAfter20Rounds)
	if !shared.AreByteSlicesEqual(serializedState, expectedSerializedState) {
		t.Error("something is wrong with serialization")
	}
}

func Test_Cipher(t *testing.T) {
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	nonce := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00,
	}
	blockCounter := uint32(1)

	cc := New(key, nonce, blockCounter)

	plainText := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	expectedCipherText := []byte{
		0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
		0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
		0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
		0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
		0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
		0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
		0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
		0x87, 0x4d,
	}

	cipherText := cc.Cipher([]byte(plainText))
	if !shared.AreByteSlicesEqual(cipherText, expectedCipherText) {
		t.Error("plain text -> cipher text failed")
	}

	decipheredPlainText := cc.Cipher(cipherText)
	if string(decipheredPlainText) != plainText {
		t.Error("cipher text -> plain text failed")
	}
}

// Test_SyncAsync checks if sync and async versions
// produces the same output
func Test_SyncAsync(t *testing.T) {
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	nonce := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00,
	}
	blockCounter := uint32(1)

	cc1 := New(key, nonce, blockCounter)
	cc2 := New(key, nonce, blockCounter)

	plainText := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

	sc := cc1.Cipher([]byte(plainText))
	ac := cc2.CipherAsync([]byte(plainText))
	if !shared.AreByteSlicesEqual(sc, ac) {
		t.Error("encrypted data are not equal")
	}

	rsc := cc1.Cipher(sc)
	rac := cc2.CipherAsync(ac)
	if string(rsc) != string(rac) {
		t.Error("decrypted data are not the same")
	}
}

// go test -bench=. -cpu 2,4,6,8 ./...

func BenchmarkCiperSync(b *testing.B) {
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	nonce := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00,
	}
	blockCounter := uint32(1)

	cc := New(key, nonce, blockCounter)

	plainText := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

	for n := 0; n < b.N; n++ {
		cc.Cipher([]byte(plainText))
	}
}

var result []byte

func BenchmarkCiperAsync(b *testing.B) {
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	nonce := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00,
	}
	blockCounter := uint32(1)

	cc := New(key, nonce, blockCounter)

	plainText := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plainText += "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

	var r []byte
	for n := 0; n < b.N; n++ {
		r = cc.CipherAsync([]byte(plainText))
	}
	result = r
}