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
	"fmt"
	"strings"
)

// ChaCha cipher object declaration
type ChaCha struct {
	key        []uint32 // A 256-bit key, 8 x uint32, 32 x byte
	nonce      []uint32 // A 96-bit nonce, 3 x uint32 - Initialisation Vector
	blockCount uint32   // A 32-bit block count parameter
}

// New creates new cipher object
func New(key []byte, nonce []byte, blockCount uint32) *ChaCha {
	return &ChaCha{
		key:        bytesToWords(key),
		nonce:      bytesToWords(nonce),
		blockCount: blockCount,
	}
}

// Cipher encrypts/decrypts passed bytes slice
func (cc *ChaCha) Cipher(text []byte) []byte {
	const BlockSize uint32 = 64 // in bytes

	n := uint32(len(text))
	blocksNumber := n / BlockSize // number of whole blocks

	var (
		cipherBuffer []byte
		blockIndex   uint32
		byteIndex    uint32
	)
	state := cc.initState(0)
	for blockIndex < blocksNumber {
		block := updateStateCounter(state, blockIndex+cc.blockCount)
		keyStream := serialize(cc.block(block))
		plainText := text[byteIndex : byteIndex+64]
		cipher := xor(plainText, keyStream)
		cipherBuffer = append(cipherBuffer, cipher...)
		blockIndex++
		byteIndex += 64
	}
	if n%BlockSize != 0 {
		block := updateStateCounter(state, blockIndex+cc.blockCount)
		keyStream := serialize(cc.block(block))
		plainText := text[byteIndex:]
		cipher := xor(plainText, keyStream)
		cipherBuffer = append(cipherBuffer, cipher...)
	}
	return cipherBuffer
}

func xor(a, b []byte) []byte {
	n := len(a)
	if n == 0 || n > len(b) {
		panic("sizes of slices are invalid")
	}
	cipher := make([]byte, n)
	for i := 0; i < n; i++ {
		cipher[i] = a[i] ^ b[i]
	}
	return cipher
}

func (cc *ChaCha) block(state []uint32) []uint32 {
	workingState := dup(state)

	for i := 0; i < 10; i++ {
		innerBlock(workingState)
	}

	return add(state, workingState)
}

func innerBlock(state []uint32) {
	// 'column' round
	quarterRoundOnState(state, 0, 4, 8, 12)
	quarterRoundOnState(state, 1, 5, 9, 13)
	quarterRoundOnState(state, 2, 6, 10, 14)
	quarterRoundOnState(state, 3, 7, 11, 15)
	// 'diagonal' round
	quarterRoundOnState(state, 0, 5, 10, 15)
	quarterRoundOnState(state, 1, 6, 11, 12)
	quarterRoundOnState(state, 2, 7, 8, 13)
	quarterRoundOnState(state, 3, 4, 9, 14)
}

func quarterRoundOnState(state []uint32, i0, i1, i2, i3 int) {
	a := state[i0]
	b := state[i1]
	c := state[i2]
	d := state[i3]
	a, b, c, d = quarterRound(a, b, c, d)
	state[i0] = a
	state[i1] = b
	state[i2] = c
	state[i3] = d
}

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	// 1. round
	a += b
	d ^= a
	d = rotl32(d, 16)
	// 2. round
	c += d
	b ^= c
	b = rotl32(b, 12)
	// 3. round
	a += b
	d ^= a
	d = rotl32(d, 8)
	// 4. round
	c += d
	b ^= c
	b = rotl32(b, 7)

	return a, b, c, d
}

func updateStateCounter(state []uint32, counter uint32) []uint32 {
	state[12] = counter
	return state
}

func (cc *ChaCha) initState(blockCount uint32) []uint32 {
	state := make([]uint32, 16)
	// add constants
	state[0] = 0x61707865
	state[1] = 0x3320646e
	state[2] = 0x79622d32
	state[3] = 0x6b206574
	// add key
	for i, v := range cc.key {
		state[i+4] = v
	}
	// add block count
	state[12] = blockCount
	// add nonce
	for i, v := range cc.nonce {
		state[i+13] = v
	}

	return state
}

func add(a, b []uint32) []uint32 {
	n := len(a)
	if n == 0 || n != len(b) {
		return nil
	}

	data := make([]uint32, n)
	for i := 0; i < n; i++ {
		data[i] = a[i] + b[i]
	}
	return data
}

func dup(data []uint32) []uint32 {
	n := len(data)
	buffer := make([]uint32, n)
	copy(buffer, data)
	// for i, v := range data {
	// 	buffer[i] = v
	// }
	return buffer
}

func rotl32(v uint32, c int) uint32 {
	return ((v << c) & 0xffffffff) | (v >> (32 - c))
}

func bytesToWords(data []byte) []uint32 {
	size := len(data)
	if size/4 == 0 || size%4 != 0 {
		return nil
	}

	n := size / 4
	words := make([]uint32, n)
	i := 0 // bytes counter
	k := 0 // words counter
	for k < n {
		words[k] = bytes2word(data[i:])
		k++
		i += 4
	}
	return words
}

func serialize(data []uint32) []byte {
	n := len(data)
	if n == 0 {
		return nil
	}

	out := make([]byte, 0, n*4)
	for _, v := range data {
		out = append(out, word2bytes(v)...)
	}
	return out
}

func bytes2word(data []byte) uint32 {
	return (uint32(data[3]) << 24) | (uint32(data[2]) << 16) | (uint32(data[1]) << 8) | uint32(data[0])
}

func word2bytes(w uint32) []byte {
	out := []byte{0, 0, 0, 0}
	out[3] = byte((w >> 24) & 0xff)
	out[2] = byte((w >> 16) & 0xff)
	out[1] = byte((w >> 8) & 0xff)
	out[0] = byte(w & 0xff)
	return out
}

func areWordSlicesEqual(a, b []uint32) bool {
	n := len(a)
	if n != len(b) {
		return false
	}
	if n == 0 {
		return true
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func areByteSlicesEqual(a, b []byte) bool {
	n := len(a)
	if n != len(b) {
		return false
	}
	if n == 0 {
		return true
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func (cc *ChaCha) printWords(state []uint32) {
	for i, v := range state {
		if i%4 == 0 {
			fmt.Printf("\n")
		}
		fmt.Printf("%08x ", v)
	}
}

// PrintBytes prints formated bytes as hex
func PrintBytes(data []byte, inRow int) {
	var tokens []string

	for i, v := range data {
		if i != 0 && i%inRow == 0 {
			tokens = append(tokens, fmt.Sprintf("\n0x%02x", v))
		} else {
			tokens = append(tokens, fmt.Sprintf("0x%02x", v))
		}
	}
	fmt.Println(strings.Join(tokens, ", "))
}
