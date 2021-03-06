package main

import (
	"fmt"

	"ChaCha-Go/chacha"
	"ChaCha-Go/shared"
)

func main() {
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
	blockCount := uint32(1)

	text := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

	cc := chacha.New(key, nonce, blockCount)
	result := cc.Cipher([]byte(text))
	shared.PrintBytes(result, 16)

	txt := cc.Cipher(result)
	fmt.Println()
	fmt.Printf("|%s|\n", string(txt))
	fmt.Println()

	result = cc.CipherAsync([]byte(text))
	shared.PrintBytes(result, 16)
	txt = cc.CipherAsync(result)
	fmt.Println()
	fmt.Printf("|%s|\n", string(txt))
	fmt.Println()
}
