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
	"sync"
)

type CipherData struct {
	index int
	data  []byte
}

func newEmptyCipherData() interface{} {
	return new(CipherData)
}

var cipherDataPool sync.Pool = sync.Pool{New: newEmptyCipherData}

func init() {
	for i := 0; i < 10; i++ {
		cipherDataPool.Put(newEmptyCipherData())
	}
}

// CipherAsync encryption/decryption using goroutines
func (cc *ChaCha) CipherAsync(text []byte) []byte {
	nbytes := len(text)
	blocksNumber := nbytes / blockSize
	extraBlock := nbytes%blockSize != 0
	goroutinesNumber := blocksNumber
	if extraBlock {
		goroutinesNumber++
	}

	cipherBuffer := make([]byte, nbytes)
	dataChan := make(chan interface{}, goroutinesNumber)
	defer close(dataChan)

	var (
		blockIndex int
		byteIndex  int
	)
	for blockIndex < blocksNumber {
		count := uint32(blockIndex) + cc.blockCount
		processedText := text[byteIndex : byteIndex+64]
		go cc.cipherBlock(count, processedText, byteIndex, dataChan)
		blockIndex++
		byteIndex += 64
	}
	if extraBlock {
		count := uint32(blockIndex) + cc.blockCount
		processedText := text[byteIndex:]
		go cc.cipherBlock(count, processedText, byteIndex, dataChan)
	}

	for i := 0; i < goroutinesNumber; i++ {
		result := <-dataChan
		cd := result.(*CipherData)
		copy(cipherBuffer[cd.index:cd.index+len(cd.data)], cd.data)
		cipherDataPool.Put(cd)
	}

	return cipherBuffer
}

func (cc *ChaCha) cipherBlock(
	counter uint32,
	text []byte,
	index int,
	dataChan chan<- interface{},
) {
	state := cc.InitState(counter)
	keyStream := Serialize(Block(state))

	cd := cipherDataPool.Get().(*CipherData)
	cd.index = index
	cd.data = xor(text, keyStream)

	dataChan <- cd
}
