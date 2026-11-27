// Package diagnostics defines the encrypted record format shared by agents and panels.
package diagnostics

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/cloudflare/circl/hpke"
)

const (
	Version          = 1
	MaxPlaintextSize = 256 << 10
	keySize          = 32
	tagSize          = 16
	headerSize       = 1 + 16 + 16 + 8 + sha256.Size
	MaxEnvelopeSize  = headerSize + keySize + MaxPlaintextSize + tagSize
)

const info = "komari.diagnostics.envelope.v1"

var (
	suite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	kem   = hpke.KEM_X25519_HKDF_SHA256.Scheme()

	ErrEnvelope = errors.New("invalid diagnostic envelope")
	ErrKey      = errors.New("invalid diagnostic key")
)

// Header is visible to relays and authenticated as associated data. Node and
// Stream are opaque 16-byte identifiers. Sequence numbers start at one.
type Header struct {
	Node     [16]byte
	Stream   [16]byte
	Sequence uint64
	KeyID    [sha256.Size]byte
}

func GenerateKey() (publicKey, privateKey []byte, err error) {
	public, private, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	publicKey, err = public.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	privateKey, err = private.MarshalBinary()
	return publicKey, privateKey, err
}

// Seal creates a one-record HPKE envelope. The caller supplies the trusted
// panel public key. Delivery must separately authenticate the sending Agent.
func Seal(publicKey []byte, header Header, record []byte) ([]byte, error) {
	if !header.validStream() || len(record) == 0 || len(record) > MaxPlaintextSize {
		return nil, ErrEnvelope
	}
	public, err := kem.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, ErrKey
	}
	header.KeyID = sha256.Sum256(publicKey)
	associated := header.encode()
	sender, err := suite.NewSender(public, []byte(info))
	if err != nil {
		return nil, ErrKey
	}
	encapsulated, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, ErrKey
	}
	ciphertext, err := sealer.Seal(record, associated[:])
	if err != nil {
		return nil, ErrEnvelope
	}
	result := make([]byte, 0, len(associated)+len(encapsulated)+len(ciphertext))
	result = append(result, associated[:]...)
	result = append(result, encapsulated...)
	return append(result, ciphertext...), nil
}

// Inspect validates the framing without decrypting. The returned metadata is
// untrusted until the caller verifies the sending identity and opens the record.
func Inspect(envelope []byte) (Header, error) {
	if len(envelope) <= headerSize+keySize+tagSize || len(envelope) > MaxEnvelopeSize || envelope[0] != Version {
		return Header{}, ErrEnvelope
	}
	var header Header
	copy(header.Node[:], envelope[1:17])
	copy(header.Stream[:], envelope[17:33])
	header.Sequence = binary.BigEndian.Uint64(envelope[33:41])
	copy(header.KeyID[:], envelope[41:headerSize])
	if !header.validStream() || header.KeyID == ([sha256.Size]byte{}) {
		return Header{}, ErrEnvelope
	}
	return header, nil
}

// Open decrypts one record and validates its header. Callers must authorize any
// disclosure of the returned plaintext.
func Open(privateKey, envelope []byte) (Header, []byte, error) {
	header, err := Inspect(envelope)
	if err != nil {
		return Header{}, nil, err
	}
	private, err := kem.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return Header{}, nil, ErrKey
	}
	publicKey, err := private.Public().MarshalBinary()
	if err != nil || sha256.Sum256(publicKey) != header.KeyID {
		return Header{}, nil, ErrKey
	}
	receiver, err := suite.NewReceiver(private, []byte(info))
	if err != nil {
		return Header{}, nil, ErrKey
	}
	opener, err := receiver.Setup(envelope[headerSize : headerSize+keySize])
	if err != nil {
		return Header{}, nil, ErrEnvelope
	}
	record, err := opener.Open(envelope[headerSize+keySize:], envelope[:headerSize])
	if err != nil {
		return Header{}, nil, ErrEnvelope
	}
	return header, record, nil
}

func (h Header) validStream() bool {
	return h.Node != ([16]byte{}) && h.Stream != ([16]byte{}) && h.Sequence != 0
}

func (h Header) encode() [headerSize]byte {
	var data [headerSize]byte
	data[0] = Version
	copy(data[1:17], h.Node[:])
	copy(data[17:33], h.Stream[:])
	binary.BigEndian.PutUint64(data[33:41], h.Sequence)
	copy(data[41:], h.KeyID[:])
	return data
}
