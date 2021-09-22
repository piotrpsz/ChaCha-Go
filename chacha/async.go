package chacha

type cipherData struct {
	index int
	data  []byte
}

func NewCipherData(index int, data []byte) *cipherData {
	return &cipherData{
		index: index,
		data:  data,
	}
}

func (cc *ChaCha) CipherAsync(text []byte) []byte {
	nbytes := len(text)
	blocksNumber := nbytes / BlockSize
	extraBlock := nbytes%BlockSize != 0
	goroutinesNumber := blocksNumber
	if extraBlock {
		goroutinesNumber += 1
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
		count := uint32(blockIndex)+cc.blockCount
		processedText := text[byteIndex:byteIndex+64]
		go cc.cipherBlock(state, count, processedText, byteIndex, dataChan)
		blockIndex++
		byteIndex += 64
	}
	if extraBlock {
		count := uint32(blockIndex)+cc.blockCount
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
	dataChan <- NewCipherData(index, cipher)
}

/*
func (cc *ChaCha) Cipher(text []byte) []byte {
	const BlockSize uint32 = 64 // in bytes

	n := uint32(len(text))
	blocksNumber := n / BlockSize // number of whole blocks

	var (
		cipherBuffer []byte
		blockIndex   uint32
		byteIndex    uint32
	)
	state := cc.InitState(0)
	for blockIndex < blocksNumber {
		block := updateStateCounter(state, blockIndex+cc.blockCount)
		keyStream := Serialize(cc.Block(block))
		plainText := text[byteIndex : byteIndex+64]
		cipher := xor(plainText, keyStream)
		cipherBuffer = append(cipherBuffer, cipher...)
		blockIndex++
		byteIndex += 64
	}
	if n%BlockSize != 0 {
		block := updateStateCounter(state, blockIndex+cc.blockCount)
		keyStream := Serialize(cc.Block(block))
		plainText := text[byteIndex:]
		cipher := xor(plainText, keyStream)
		cipherBuffer = append(cipherBuffer, cipher...)
	}
	return cipherBuffer
}
*/
