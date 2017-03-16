package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/sigpb"
)

const rsaKeySizeInBits = 4096

// PEMKeyProvider loads PEM-encoded private keys.
// It only supports trees whose PrivateKey field is a trillian.PEMKeyFile.
// It implements keys.Provider.
// TODO(robpercival): Should this cache loaded private keys? The SequenceManager will request a signer for each batch of leaves it sequences.
type PEMKeyProvider struct{}

// Signer returns a crypto.Signer for the given tree.
func (p PEMKeyProvider) Signer(ctx context.Context, tree *trillian.Tree) (crypto.Signer, error) {
	key, err := unmarshalPrivateKey(tree)
	if err != nil {
		return nil, err
	}

	return NewFromPrivatePEMFile(key.Path, key.Password)
}

// Generate creates a new private key for the given tree.
// If the tree specifies ECDSA as the signature algorithm, a P-256 EC private key will be generated.
// If the tree specifies RSA as the signature algorithm, a PKCS1 4096-bit RSA private key will be generated.
// This private key will be written to disk with file permissions 0400.
// If the tree specifies a password for the private key, it will be encrypted using AES-256 and this password.
func (p PEMKeyProvider) Generate(ctx context.Context, tree *trillian.Tree) error {
	var pemBlock pem.Block

	switch tree.GetSignatureAlgorithm() {
	case sigpb.DigitallySigned_ECDSA:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		pemBlock.Type = "EC PRIVATE KEY"
		pemBlock.Bytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
	case sigpb.DigitallySigned_RSA:
		key, err := rsa.GenerateKey(rand.Reader, rsaKeySizeInBits)
		if err != nil {
			return err
		}

		pemBlock.Type = "RSA PRIVATE KEY"
		pemBlock.Bytes = x509.MarshalPKCS1PrivateKey(key)
	default:
		return fmt.Errorf("unsupported signature algorithm: %v", tree.GetSignatureAlgorithm())
	}

	keyInfo, err := unmarshalPrivateKey(tree)
	if err != nil {
		return err
	}

	// If a password was provided, encrypt the private key using it.
	if keyInfo.Password != "" {
		pemBlock, err = x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, []byte(keyInfo.Password), x509.PEMCipherAES256)
		if err != nil {
			return err
		}
	}

	// Create a file for the private key:
	// - must not already exist.
	// - will only be readable by the current user.
	file, err := os.OpenFile(keyInfo.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}

	// Write the private key to the file.
	return pem.Encode(file, &pemBlock)
}

func unmarshalPrivateKey(tree *trillian.Tree) (*trillian.PEMKeyFile, error) {
	if tree.PrivateKey == nil {
		return nil, fmt.Errorf("tree %d has no PrivateKey", tree.GetTreeId())
	}

	var privateKey ptypes.DynamicAny
	if err := ptypes.UnmarshalAny(tree.PrivateKey, &privateKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key for tree %d: %v", tree.GetTreeId(), err)
	}

	switch privateKey := privateKey.Message.(type) {
	case *trillian.PEMKeyFile:
		return privateKey
	}

	return nil, fmt.Errorf("unsupported PrivateKey type for tree %d: %T", tree.GetTreeId(), privateKey.Message)
}
