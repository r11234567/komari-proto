package diagnostics

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

var ErrReceipt = errors.New("invalid diagnostic receipt")

const receiptDomain = "komari.diagnostics.receipt.v1\x00"

// Receipt binds a receiver's clock reading to the exact encrypted bytes.
type Receipt struct {
	Digest     [sha256.Size]byte
	ReceivedAt time.Time
	Signature  []byte
}

// SignReceipt is called after the encrypted record is committed to storage.
// Its signing key is distinct from the key that opens records.
func SignReceipt(key ed25519.PrivateKey, envelope []byte, receivedAt time.Time) (Receipt, error) {
	if len(key) != ed25519.PrivateKeySize || !receiptTimeValid(receivedAt) {
		return Receipt{}, ErrReceipt
	}
	if _, err := Inspect(envelope); err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{Digest: sha256.Sum256(envelope), ReceivedAt: receivedAt.UTC()}
	receipt.Signature = ed25519.Sign(key, receipt.signingInput())
	return receipt, nil
}

func (r Receipt) Verify(key ed25519.PublicKey, envelope []byte) error {
	if len(key) != ed25519.PublicKeySize || !receiptTimeValid(r.ReceivedAt) {
		return ErrReceipt
	}
	if _, err := Inspect(envelope); err != nil {
		return err
	}
	if sha256.Sum256(envelope) != r.Digest || !ed25519.Verify(key, r.signingInput(), r.Signature) {
		return ErrReceipt
	}
	return nil
}

func (r Receipt) signingInput() []byte {
	input := append([]byte(receiptDomain), r.Digest[:]...)
	input = binary.BigEndian.AppendUint64(input, uint64(r.ReceivedAt.Unix()))
	return binary.BigEndian.AppendUint32(input, uint32(r.ReceivedAt.Nanosecond()))
}

func receiptTimeValid(at time.Time) bool { return at.Unix() > 0 && at.Year() <= 9999 }
