package poly1305

/*
Poly1305 to jednorazowy uwierzytelniacz zaprojektowany przez D.J. Bernsteina.
Poly1305 pobiera 32-bajtowy jednorazowy klucz i wiadomość i tworzy
16-bajtowy znacznik. Ten tag służy do uwierzytelniania wiadomości.
*/

type Poly1305 struct {
	key     []byte // A 256-bit key, 8 x uint32, 32 x byte
	message []byte
}

func New(key []byte) *Poly1305 {
	if len(key) == 32 {
		return &Poly1305{
			key:     key,
			message: nil,
		}
	}
	return nil
}

func mac(key, message []byte) []byte {
	P := 2e130 - 5
	accumulator := 0

}

//
// func generateKey(key, nonce []byte) []byte {
// 	cc := chacha.New(key, nonce, uint32(0))
//
// }

func clamp(r []byte) {
	r[3] &= 15
	r[7] &= 15
	r[11] &= 15
	r[15] &= 15
	r[4] &= 252
	r[8] &= 252
	r[12] &= 252
}
