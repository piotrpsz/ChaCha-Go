# ChaCha-Go
ChaCha20 implementation in Go.<br>
ChaCha20 algoritm implementation based on RFC 8439<br>
<i>(ChaCha20 and Poly1305 for IETF Protocols)</i><br><br>
RFC 8439: https://datatracker.ietf.org/doc/html/rfc8439
<br><br>
The standard encryption function works synchronously (blocks are encrypted one by one), if large amounts of data are encrypted, consider using the asynchronous version (individual blocks are encrypted in dedicated go-routines)