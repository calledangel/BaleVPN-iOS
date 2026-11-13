package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

const maxObject = 3 << 20

var ErrInvalidObject = errors.New("invalid encrypted FlowDriver object")

type encryptedBackend struct {
	Backend
	cipher cipher.AEAD
	prefix string
}

func Encrypted(backend Backend, key []byte) (Backend, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	namespace := sha256.Sum256(append([]byte("flowdriver-storage-v1:"), key...))
	prefix := "flow-v1-" + hex.EncodeToString(namespace[:12]) + "-"
	return &encryptedBackend{Backend: backend, cipher: gcm, prefix: prefix}, nil
}

func (b *encryptedBackend) Upload(ctx context.Context, name string, data io.Reader) error {
	plaintext, err := io.ReadAll(io.LimitReader(data, maxObject+1))
	if err != nil || len(plaintext) > maxObject {
		return ErrInvalidObject
	}
	name = b.prefix + name
	sealed := b.cipher.Seal(nil, nil, plaintext, []byte(name))
	return b.Backend.Upload(ctx, name, bytes.NewReader(sealed))
}

func (b *encryptedBackend) ListQuery(ctx context.Context, prefix string) ([]string, error) {
	names, err := b.Backend.ListQuery(ctx, b.prefix+prefix)
	if err != nil {
		return nil, err
	}
	selected := names[:0]
	for _, name := range names {
		if logical, ok := strings.CutPrefix(name, b.prefix); ok && strings.HasPrefix(logical, prefix) {
			selected = append(selected, logical)
		}
	}
	return selected, nil
}

func (b *encryptedBackend) Download(ctx context.Context, name string) (io.ReadCloser, error) {
	name = b.prefix + name
	source, err := b.Backend.Download(ctx, name)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	limit := int64(maxObject + b.cipher.Overhead())
	sealed, err := io.ReadAll(io.LimitReader(source, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(sealed)) > limit {
		return nil, ErrInvalidObject
	}
	plaintext, err := b.cipher.Open(nil, nil, sealed, []byte(name))
	if err != nil {
		return nil, ErrInvalidObject
	}
	return io.NopCloser(bytes.NewReader(plaintext)), nil
}

func (b *encryptedBackend) Delete(ctx context.Context, name string) error {
	return b.Backend.Delete(ctx, b.prefix+name)
}
