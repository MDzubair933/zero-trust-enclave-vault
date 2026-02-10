package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type EnvelopeEngine struct {
	masterKey []byte
}

func NewEnvelopeEngine(masterKey []byte) (*EnvelopeEngine, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes (AES-256)")
	}
	return &EnvelopeEngine{masterKey: masterKey}, nil
}

func (e *EnvelopeEngine) EncryptSecret(plaintext []byte) (cipherText, nonce []byte, err error) {
	block, err := aes.NewCipher(e.masterKey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	cipherText = gcm.Seal(nil, nonce, plaintext, nil)
	return cipherText, nonce, nil
}
