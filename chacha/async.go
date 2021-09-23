package chacha

import (
	"sync"
)

type cipherData struct {
	index int
	data  []byte
}

func newEmptyCipherData() interface{} {
	return &cipherData{}
}

func newCipherData(index int, data []byte) *cipherData {
	return &cipherData{
		index: index,
		data:  data,
	}
}

var pool *sync.Pool = &sync.Pool{New: newEmptyCipherData}

func init() {
	for i := 0; i < 10; i++ {
		pool.Put(pool.New)
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
	state := cc.InitState(0)
	for blockIndex < blocksNumber {
		count := uint32(blockIndex) + cc.blockCount
		processedText := text[byteIndex : byteIndex+64]
		go cc.cipherBlock(state, count, processedText, byteIndex, dataChan)
		blockIndex++
		byteIndex += 64
	}
	if extraBlock {
		count := uint32(blockIndex) + cc.blockCount
		processedText := text[byteIndex:]
		go cc.cipherBlock(state, count, processedText, byteIndex, dataChan)
	}

	for i := 0; i < goroutinesNumber; i++ {
		result := <-dataChan
		data := result.(*cipherData)
		copy(cipherBuffer[data.index:data.index+len(data.data)], data.data)
		pool.Put(result)
	}

	return cipherBuffer
}

func (cc *ChaCha) cipherBlock(
	state []uint32,
	counter uint32,
	text []byte,
	index int,
	dataChan chan<- interface{},
) {
	block := updateStateCounter(state, counter)
	keyStream := Serialize(cc.Block(block))
	cipher := xor(text, keyStream)
	data := *pool.Get().(*cipherData)

	data.index = index
	data.data = cipher
	dataChan <- data
}
