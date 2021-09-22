package chacha

type cipherData struct {
	index int
	data  []byte
}

func newCipherData(index int, data []byte) *cipherData {
	return &cipherData{
		index: index,
		data:  data,
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
	dataChan := make(chan *cipherData, goroutinesNumber)
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
		copy(cipherBuffer[result.index:result.index+len(result.data)], result.data)
	}

	return cipherBuffer
}

func (cc *ChaCha) cipherBlock(
	state []uint32,
	counter uint32,
	text []byte,
	index int,
	dataChan chan<- *cipherData,
) {
	block := updateStateCounter(state, counter)
	keyStream := Serialize(cc.Block(block))
	cipher := xor(text, keyStream)
	dataChan <- newCipherData(index, cipher)
}
