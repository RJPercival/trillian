// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"
)

// PKCS11SignerFactory retrieves keys using a PKCS#11 module.
// Such modules typically provide access to hardware security modules (HSMs).
// It supports trees whose PrivateKey field is a keyspb.PKCS11Config.
// It implements keys.SignerFactory.
type PKCS11SignerFactory struct {
	modulePath string
}

// NewPKCS11SignerFactory returns a PKCS11SignerFactory that uses the specified PKCS#11 module to retrieve keys.
// The modulePath must identify a library to load, e.g. "/usr/lib/opensc-ppkcs11.so".
func NewPKCS11SignerFactory(modulePath string) *PKCS11SignerFactory {
	return &PKCS11SignerFactory{
		modulePath: modulePath,
	}
}

// NewSigner returns a crypto.Signer for the given tree.
func (f PEMSignerFactory) NewSigner(ctx context.Context, tree *trillian.Tree, pkcs11Module string) (crypto.Signer, error) {
	if tree.GetPrivateKey() == nil {
		return nil, fmt.Errorf("tree %d has no PrivateKey", tree.GetTreeId())
	}

	var privateKey ptypes.DynamicAny
	if err := ptypes.UnmarshalAny(tree.GetPrivateKey(), &privateKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key for tree %d: %v", tree.GetTreeId(), err)
	}

	switch privateKey := privateKey.Message.(type) {
	case *keyspb.PKCS11Config:
		return NewFromPKCS11Config(f.modulePath, privateKey)
	}

	return nil, fmt.Errorf("unsupported PrivateKey type for tree %d: %T", tree.GetTreeId(), privateKey.Message)
}

// Generate creates a new private key for a tree based on a key specification.
// It returns a proto that can be used as the value of tree.PrivateKey.
func (f PEMSignerFactory) Generate(ctx context.Context, tree *trillian.Tree, spec *keyspb.Specification) (*any.Any, error) {
	return errors.New("Generate() not implemented")
}
