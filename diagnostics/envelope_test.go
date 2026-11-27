package diagnostics

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"
)

func TestEncryptedRecordAuthenticatesFraming(t *testing.T) {
	public, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	header := Header{Node: [16]byte{1}, Stream: [16]byte{2}, Sequence: 1}
	payload := bytes.Repeat([]byte("synthetic application data\n"), 1000)
	sealed, err := Seal(public, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal(public, header, payload)
	if err != nil || bytes.Equal(sealed, second) {
		t.Fatalf("records must use independent HPKE contexts: %v", err)
	}
	if bytes.Contains(sealed, []byte("synthetic application data")) {
		t.Fatal("plaintext found in envelope")
	}
	header.KeyID = sha256.Sum256(public)
	got, plaintext, err := Open(private, sealed)
	if err != nil || got != header || !bytes.Equal(plaintext, payload) {
		t.Fatalf("round trip failed: %v", err)
	}
	for _, offset := range []int{0, 1, 17, 33, 41, headerSize, len(sealed) - 1} {
		broken := bytes.Clone(sealed)
		broken[offset] ^= 0x80
		if _, _, err := Open(private, broken); err == nil {
			t.Fatalf("tampering at byte %d was accepted", offset)
		}
	}
	_, wrongKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(wrongKey, sealed); err == nil {
		t.Fatal("a different panel key opened the record")
	}
}

func TestReceiptBindsTimeAndCiphertext(t *testing.T) {
	public, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	verificationKey, signingKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	header := Header{Node: [16]byte{1}, Stream: [16]byte{2}, Sequence: 1}
	sealed, err := Seal(public, header, []byte("application data"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := SignReceipt(signingKey, sealed, time.Now())
	if err != nil || receipt.Verify(verificationKey, sealed) != nil {
		t.Fatalf("receipt round trip failed: %v", err)
	}
	revised, err := Seal(public, header, []byte("another record"))
	if err != nil || receipt.Verify(verificationKey, revised) == nil {
		t.Fatalf("receipt accepted a different record: %v", err)
	}
	receipt.ReceivedAt = receipt.ReceivedAt.Add(time.Nanosecond)
	if receipt.Verify(verificationKey, sealed) == nil {
		t.Fatal("receipt accepted a different timestamp")
	}
}

func TestRecordBounds(t *testing.T) {
	public, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	header := Header{Node: [16]byte{1}, Stream: [16]byte{2}, Sequence: 1}
	if _, err := Seal(public, header, make([]byte, MaxPlaintextSize+1)); err == nil {
		t.Fatal("accepted oversized plaintext")
	}
	if _, err := Seal(public, header, nil); err == nil {
		t.Fatal("accepted empty plaintext")
	}
	if _, err := Seal(public, Header{}, []byte{1}); err == nil {
		t.Fatal("accepted missing record identity")
	}
	sealed, err := Seal(public, header, make([]byte, MaxPlaintextSize))
	if err != nil || len(sealed) != MaxEnvelopeSize {
		t.Fatalf("maximum size envelope = %d, error = %v", len(sealed), err)
	}
	if _, err := Inspect(append(sealed, 0)); err == nil {
		t.Fatal("accepted oversized envelope")
	}
	if _, err := Inspect(sealed[:headerSize]); err == nil {
		t.Fatal("accepted a header without a record")
	}
}
