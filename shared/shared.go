package shared

import (
	"fmt"
	"strings"
)

func AreWordSlicesEqual(a, b []uint32) bool {
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

func AreByteSlicesEqual(a, b []byte) bool {
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

func PrintWords(state []uint32) {
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
