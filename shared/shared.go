package shared

import (
	"fmt"
	"strings"
)

// AreWordSlicesEqual checks if two
// passed uint32 slices are equal
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

// AreByteSlicesEqual checks if two
// passed byte slices are equal
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

// PrintWords prints uint32 slice as hex values
func PrintWords(state []uint32) {
	for i, v := range state {
		if i%4 == 0 {
			fmt.Printf("\n")
		}
		fmt.Printf("%08x ", v)
	}
}

// PrintBytes prints formated bytes as hex values
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

func PrintInfo(title string, a, b []byte) {
	fmt.Println()
	fmt.Println("[source text]", title)
	PrintBytes(a, 16)
	fmt.Println("[cipher result]")
	PrintBytes(b, 16)
	fmt.Println()
}