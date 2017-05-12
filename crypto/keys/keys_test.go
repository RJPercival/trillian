// Copyright 2016 Google Inc. All Rights Reserved.
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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/testonly"
)

const (
	ecdsaPublicKey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvuynpVdR+5xSNaVBb//1fqO6Nb/nC+WvRQ4bALzy4G+QbByvO1Qpm2eUzTdDUnsLN5hp3pIXYAmtjvjY1fFZEg==
-----END PUBLIC KEY-----`
	ecdsaPrivateKey = `
-----BEGIN PRIVATE KEY-----
MHcCAQEEIHG5m/q2sUSa4P8pRZgYt3K0ESFSKp1qp15VjJhpLle4oAoGCCqGSM49AwEHoUQDQgAEvuynpVdR+5xSNaVBb//1fqO6Nb/nC+WvRQ4bALzy4G+QbByvO1Qpm2eUzTdDUnsLN5hp3pIXYAmtjvjY1fFZEg==
-----END PRIVATE KEY-----
`
	rsaPublicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMB4reLZhs+2ReYX01nZpqLBQ9uhcZvBmzH54RsZDTb5khw+luSXKbLKXxdbQfrsxURbeVdugDNnV897VI43znuiKJ19Y/XS3N5Z7Q97/GOxOxGFObP0DovCAPblxAMaQBb+U9jkVt/4bHcNIOTZl/lXgX+yp58lH5uPfDwav/hVNg7QkAW3BxQZ5wiLTTZUILoTMjax4R24pULlg/Wt/rT4bDj8rxUgYR60MuO93jdBtNGwmzdCYyk4cEmrPEgCueRC6jFafUzlLjvuX89ES9n98LxX+gBANA7RpVPkJd0kfWFHO1JRUEJr++WjU3x4la2Xs4tUNX4QBSJP4XEOXwIDAQAB
-----END PUBLIC KEY-----`
	rsaPrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCwwHit4tmGz7ZF5hfTWdmmosFD26Fxm8GbMfnhGxkNNvmSHD6W5JcpsspfF1tB+uzFRFt5V26AM2dXz3tUjjfOe6IonX1j9dLc3lntD3v8Y7E7EYU5s/QOi8IA9uXEAxpAFv5T2ORW3/hsdw0g5NmX+VeBf7KnnyUfm498PBq/+FU2DtCQBbcHFBnnCItNNlQguhMyNrHhHbilQuWD9a3+tPhsOPyvFSBhHrQy473eN0G00bCbN0JjKThwSas8SAK55ELqMVp9TOUuO+5fz0RL2f3wvFf6AEA0DtGlU+Ql3SR9YUc7UlFQQmv75aNTfHiVrZezi1Q1fhAFIk/hcQ5fAgMBAAECggEAcpuq5J2GjQqcVwCWjF3jalB4XsbIDUGArWAfdd47RT1TYHFeCDua5Nfgrv4XF1ZcNqFXavvNU+WA6ghIIRDCkOnLwOg1yR45pyuqRbPXolUGM5Xtu/e6lb/7gOKXI50bZVlDehzWGprJm5MqeRzLFub/3aFut4/S44bb6COU+Mo6bsm+/2hcuOtUeDR5fOc49tTAZZSG6kVAXdWG5raU4a/Qx6LCR5zMjhzqy8FMGkW+eww243WM/5RCW6pzgwjFVPyfrg/Jqc2IgAPuFEStvK6jAsPaZxb7t1ue79ku8+xLDpJSgLUF3jU9Qy8+VphnmbHrYSqDSNUyfj8+qcbI0QKBgQDc/GD7Yprw4zp3IqLoYd96dqJtlloUgd7kGebDfAftAgo2ooS8tpbAYGvgmeMDqAfqfTkOJUACCHptnpUWusXJqW6SW9bk17jGb/pPcQiXmaNPGYbpPlamueUmS9gdatvw6iXewRqjltNMng+mfbvAmaFe+qeqCq86R9BoUFVBCQKBgQDMwd+6DKGKH/hgChweUtNLMmeOmzYskcUL43cLeAAwwlL4DruLthBb/0SYeMQ+sXpYDL3b1/i03Ln5P5g8KFL8EgIayInlZJHiHjOn9LF+S5gv5snI0Fdk2O8eNHCSiS0+qqPU8ZKTKwnbt8M+OqLhJD0C7N35oYAoCj0uhSp2JwKBgQDBIxqn2tBMBGyOvwjeTNwCrjjbynJERhVGCpUy+O38aLIAeh3EyVgMHrlp/VT5VxxEBtmc0VWV8U7/C4CF8wr2a0ymQfoY26k0VZ3RXJsD1FV0xnyw0bjt0r7Br7vcSg6cCii6/M6Jd0KJTgOjoXQ8qojs9+kdpmTrbORqpvs78QKBgQC13ZW8CLAKoS7ZDuG+xU5LQi/c6FuL5sWgM59vHlz88f0DuwI1q7aIIAlrbAjSroy+XELeW8vZyRueGTA8boyWu+AGrgxdJaC1uKGlEp/8T2STV2fu565YMp7gsy8x2InJWYM/BnpsIRQWhffy893sH2XZjU30BdBwv/drtHfsjQKBgHQgInEA+pwo/laVgVkuIlL/0avlRRG06TsMUJYDP9jOfzdoWZrsCVr4uLXMR1zJ2I/tmKv+u+35luu2rVnItB7hSJgMy+6Bxj4DL5QE9BuLVARDMGrj05oZXPw9954HjN87b4dVvSKl2hPz6lcsKDlPJy+OvXdsZxfc9NaCCQNT
-----END PRIVATE KEY-----
`
	dsaPublicKey = `
-----BEGIN PUBLIC KEY-----
MIIDRjCCAjkGByqGSM44BAEwggIsAoIBAQDgLI6pXvqpcOY33lzeZrjUBHxphiz0I9VKF9vGpWymNfBptQ75bpQFe16jBjaOGwDImASHTp53XskQJLOXC4bZxoRUHsm8bHQVZHQhYgxn8ZDQX/40zOR1d73y1TXSiULo6rDKVlM+fFcm33tGv+ZOdfaIhW17c5jvDAy6UWqQakasvL+kfiejIDGHjLVFWwX0vLCG+pAomgO6snQHGcPhDO9uxEYPd9on7YTgBrpa2IcXk5jFeY8xOxMnMwoBojRvH97+ivdBR1yW8f+4FAGg5o1eFV5ZqoUAF8GO3BBEwluMGNeT7gMgl4PO8N8xBxJulHd3tLW5qkW0cBPwkbzzAiEAvdYeMPamsFAyd7s07dt78wxXyHGrwVl2AcQBo0QTATkCggEASH9Rp+EjNkL7uCqGJ78P4tjJM+2+xaEhZpJ/kTzq6DtdFhu5Rov6lN5NnZKPSUNYr9Vkmu88ru0iND1N37z0rJpImksXKxCv0AwBkwtqCwf9jjkTrZiGRzP8xf789wK+uG7Uud20ml9QzXKr9Af9WrRx3DtCq44PBaIlhPvpZS9znCZsuUZqYZFW3/oD4EhwPgVLSWeulh1t33ku3mYQwVS8ZTdJGPyFRoD1dcQ4EchR4ce0u0nTXlqErWhfnmb9msF6dFCV0Mx5yrqxkEHbJ/vZgB4zAdOke7XiJsWqIok/7IJpJuVOvkY9NHgBdlq3xU180+pEo2NrGm4pbrGm1wOCAQUAAoIBAAGbucHEfgtcu++OQQjYqneukv4zqcP/PCJTP+GuXen6SH25V2ZlHC88lG6qdZVBPWZidAb9BSoUQpW7BzauKRqH7rKOsIeqvEPCiWBKA781Zi5HAWGhC4INJJx54Q66F54DkGlTRVFkXlGpAIudhfAIG//MyO9TIsLSgRyqjKWVm+/XhWDIT5iMJZZ/IgmbICueaa7go8poHuTTyUDPHPIeL5d9Aru7qD4JtX+UVy6GYKhWx/guv+A7zyJ8d1kMLsmUAro80DLPDoais2I8YPpbu+xTSLLswIYddDdwg3P8mMAGzuWY/ZLumwpRr/fbI+t2Sm9KKGNGkGGIKAg43cs=
-----END PUBLIC KEY-----`
	corruptEcdsaPrivateKey = `
-----BEGIN PRIVATE KEY-----
NHcCAQEEIHG5m/q2sUSa4P8pRZgYt3K0ESFSKp1qp15VjJhpLle4oAoGCCqGSM49AwEHoUQDQgAEvuynpVdR+5xSNaVBb//1fqO6Nb/nC+WvRQ4bALzy4G+QbByvO1Qpm2eUzTdDUnsLN5hp3pIXYAmtjvjY1fFZEg==
-----END PRIVATE KEY-----
`
)

func verifyECDSA(key *ecdsa.PublicKey, digest []byte, signature []byte) error {
	// s is the decoded signature.
	var s struct {
		R, S *big.Int
	}

	_, err := asn1.Unmarshal(signature, &s)
	if err != nil {
		return fmt.Errorf("failed to unmarshal signature as ASN.1: %v", err)
	}

	if !ecdsa.Verify(key, digest, s.R, s.S) {
		return errors.New("signature failed verification")
	}

	return nil
}

func TestLoadPrivateKeyAndSign(t *testing.T) {
	hasher := crypto.SHA256
	digest := []byte("\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24")

	tests := []struct {
		name        string
		keyPEM      string
		keyPath     string
		keyPass     string
		wantLoadErr bool
	}{
		{
			name:    "ECDSA with password",
			keyPEM:  testonly.DemoPrivateKey,
			keyPass: testonly.DemoPrivateKeyPass,
		},
		{
			name:    "ECDSA from file with password",
			keyPath: "../../testdata/log-rpc-server.privkey.pem",
			keyPass: "towel",
		},
		{
			name:        "Non-existent file",
			keyPath:     "non-existent.pem",
			wantLoadErr: true,
		},
		{
			name:        "ECDSA with wrong password",
			keyPEM:      testonly.DemoPrivateKey,
			keyPass:     testonly.DemoPrivateKeyPass + "foo",
			wantLoadErr: true,
		},
		{
			name:   "ECDSA",
			keyPEM: ecdsaPrivateKey,
		},
		{
			name:   "RSA",
			keyPEM: rsaPrivateKey,
		},
		{
			name:   "ECDSA with leading junk",
			keyPEM: "foobar\n" + ecdsaPrivateKey,
		},
		{
			name:        "ECDSA with trailing junk",
			keyPEM:      ecdsaPrivateKey + "\nfoobar",
			wantLoadErr: true,
		},
		{
			name:        "Corrupt ECDSA",
			keyPEM:      corruptEcdsaPrivateKey,
			wantLoadErr: true,
		},
	}

	for _, test := range tests {
		var k crypto.Signer
		var err error
		switch {
		case test.keyPEM != "":
			k, err = NewFromPrivatePEM(test.keyPEM, test.keyPass)
			switch gotErr := err != nil; {
			case gotErr != test.wantLoadErr:
				t.Errorf("%v: NewFromPrivatePEM() = (%v, %v), want err? %v", test.name, k, err, test.wantLoadErr)
				continue
			case gotErr:
				continue
			}

		case test.keyPath != "":
			k, err = NewFromPrivatePEMFile(test.keyPath, test.keyPass)
			switch gotErr := err != nil; {
			case gotErr != test.wantLoadErr:
				t.Errorf("%v: NewFromPrivatePEMFile() = (%v, %v), want err? %v", test.name, k, err, test.wantLoadErr)
				continue
			case gotErr:
				continue
			}

		default:
			t.Errorf("%v: No PEM or file path set in test definition", test.name)
			continue
		}

		signature, err := k.Sign(rand.Reader, digest, hasher)
		if err != nil {
			t.Errorf("%v: failed to sign: %v", test.name, err)
			continue
		}

		// Do a round trip by verifying the signature using the public key.
		switch publicKey := k.Public().(type) {
		case *ecdsa.PublicKey:
			if err := verifyECDSA(publicKey, digest, signature); err != nil {
				t.Errorf("%v: %v", test.name, err)
			}
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(publicKey, hasher, digest, signature); err != nil {
				t.Errorf("%v: %v", test.name, err)
			}
		default:
			t.Errorf("%v: Unsupported public key type: %T", test.name, publicKey)
		}

	}
}

func TestSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name   string
		keyPEM string
		want   sigpb.DigitallySigned_SignatureAlgorithm
	}{
		{
			name:   "ECDSA",
			keyPEM: ecdsaPublicKey,
			want:   sigpb.DigitallySigned_ECDSA,
		},
		{
			name:   "RSA",
			keyPEM: rsaPublicKey,
			want:   sigpb.DigitallySigned_RSA,
		},
		{
			name:   "DSA",
			keyPEM: dsaPublicKey,
			want:   sigpb.DigitallySigned_ANONYMOUS,
		},
	}

	for _, test := range tests {
		key, err := NewFromPublicPEM(test.keyPEM)
		if err != nil {
			t.Errorf("%v: Failed to load key: %v", test.name, err)
			continue
		}

		if got := SignatureAlgorithm(key); got != test.want {
			t.Errorf("%v: SignatureAlgorithm(%v) = %v, want %v", test.name, key, got, test.want)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	for _, test := range []struct {
		name    string
		keygen  *keyspb.Specification
		wantErr bool
	}{
		{
			name: "ECDSA with default params",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_EcdsaParams{},
			},
		},
		{
			name: "ECDSA with explicit params",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_EcdsaParams{
					EcdsaParams: &keyspb.Specification_ECDSA{
						Curve: keyspb.Specification_ECDSA_P521,
					},
				},
			},
		},
		{
			name: "RSA with default params",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_RsaParams{},
			},
		},
		{
			name: "RSA with explicit params",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_RsaParams{
					RsaParams: &keyspb.Specification_RSA{
						Bits: 4096,
					},
				},
			},
		},
		{
			name: "RSA with negative key size",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_RsaParams{
					RsaParams: &keyspb.Specification_RSA{
						Bits: -4096,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "RSA with insufficient key size",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_RsaParams{
					RsaParams: &keyspb.Specification_RSA{
						Bits: MinRsaKeySizeInBits - 1,
					},
				},
			},
			wantErr: true,
		},
		{
			name:    "No params",
			keygen:  &keyspb.Specification{},
			wantErr: true,
		},
	} {
		key, err := NewFromSpec(test.keygen)
		if gotErr := err != nil; gotErr != test.wantErr {
			t.Errorf("%v: NewFromSpecification() = (_, %v), want err? %v", test.name, err, test.wantErr)
			continue
		} else if gotErr {
			continue
		}

		switch params := test.keygen.Params.(type) {
		case *keyspb.Specification_EcdsaParams:
			switch key := key.(type) {
			case *ecdsa.PrivateKey:
				wantCurve := curveFromParams(params.EcdsaParams)
				if wantCurve.Params().Name != key.Params().Name {
					t.Errorf("%v: NewFromSpecification() => ECDSA key on %v curve, want %v curve", test.name, key.Params().Name, wantCurve.Params().Name)
				}
			default:
				t.Errorf("%v: NewFromSpecification() = (%T, nil), want *ecdsa.PrivateKey", test.name, key)
			}
		case *keyspb.Specification_RsaParams:
			switch key := key.(type) {
			case *rsa.PrivateKey:
				wantBits := defaultRsaKeySizeInBits
				if params.RsaParams.GetBits() != 0 {
					wantBits = int(params.RsaParams.GetBits())
				}

				if got, want := key.N.BitLen(), wantBits; got != want {
					t.Errorf("%v: NewFromSpecification() => %v-bit RSA key, want %v-bit", test.name, got, want)
				}
			default:
				t.Errorf("%v: NewFromSpecification() = (%T, nil), want *rsa.PrivateKey", test.name, key)
			}
		}
	}
}

func TestMarshalKey(t *testing.T) {
	for _, test := range []struct {
		name   string
		keyDER []byte
	}{
		{
			name:   "ECDSA key",
			keyDER: mustBase64Decode("MHcCAQEEIHG5m/q2sUSa4P8pRZgYt3K0ESFSKp1qp15VjJhpLle4oAoGCCqGSM49AwEHoUQDQgAEvuynpVdR+5xSNaVBb//1fqO6Nb/nC+WvRQ4bALzy4G+QbByvO1Qpm2eUzTdDUnsLN5hp3pIXYAmtjvjY1fFZEg=="),
		},
		{
			name:   "RSA key",
			keyDER: mustBase64Decode("MIIEpAIBAAKCAQEAsMB4reLZhs+2ReYX01nZpqLBQ9uhcZvBmzH54RsZDTb5khw+luSXKbLKXxdbQfrsxURbeVdugDNnV897VI43znuiKJ19Y/XS3N5Z7Q97/GOxOxGFObP0DovCAPblxAMaQBb+U9jkVt/4bHcNIOTZl/lXgX+yp58lH5uPfDwav/hVNg7QkAW3BxQZ5wiLTTZUILoTMjax4R24pULlg/Wt/rT4bDj8rxUgYR60MuO93jdBtNGwmzdCYyk4cEmrPEgCueRC6jFafUzlLjvuX89ES9n98LxX+gBANA7RpVPkJd0kfWFHO1JRUEJr++WjU3x4la2Xs4tUNX4QBSJP4XEOXwIDAQABAoIBAHKbquSdho0KnFcAloxd42pQeF7GyA1BgK1gH3XeO0U9U2BxXgg7muTX4K7+FxdWXDahV2r7zVPlgOoISCEQwpDpy8DoNckeOacrqkWz16JVBjOV7bv3upW/+4DilyOdG2VZQ3oc1hqayZuTKnkcyxbm/92hbreP0uOG2+gjlPjKOm7Jvv9oXLjrVHg0eXznOPbUwGWUhupFQF3Vhua2lOGv0MeiwkeczI4c6svBTBpFvnsMNuN1jP+UQluqc4MIxVT8n64PyanNiIAD7hRErbyuowLD2mcW+7dbnu/ZLvPsSw6SUoC1Bd41PUMvPlaYZ5mx62Eqg0jVMn4/PqnGyNECgYEA3Pxg+2Ka8OM6dyKi6GHfenaibZZaFIHe5Bnmw3wH7QIKNqKEvLaWwGBr4JnjA6gH6n05DiVAAgh6bZ6VFrrFyaluklvW5Ne4xm/6T3EIl5mjTxmG6T5WprnlJkvYHWrb8Ool3sEao5bTTJ4Ppn27wJmhXvqnqgqvOkfQaFBVQQkCgYEAzMHfugyhih/4YAocHlLTSzJnjps2LJHFC+N3C3gAMMJS+A67i7YQW/9EmHjEPrF6WAy929f4tNy5+T+YPChS/BICGsiJ5WSR4h4zp/SxfkuYL+bJyNBXZNjvHjRwkoktPqqj1PGSkysJ27fDPjqi4SQ9Auzd+aGAKAo9LoUqdicCgYEAwSMap9rQTARsjr8I3kzcAq4428pyREYVRgqVMvjt/GiyAHodxMlYDB65af1U+VccRAbZnNFVlfFO/wuAhfMK9mtMpkH6GNupNFWd0VybA9RVdMZ8sNG47dK+wa+73EoOnAoouvzOiXdCiU4Do6F0PKqI7PfpHaZk62zkaqb7O/ECgYEAtd2VvAiwCqEu2Q7hvsVOS0Iv3Ohbi+bFoDOfbx5c/PH9A7sCNau2iCAJa2wI0q6MvlxC3lvL2ckbnhkwPG6MlrvgBq4MXSWgtbihpRKf/E9kk1dn7ueuWDKe4LMvMdiJyVmDPwZ6bCEUFoX38vPd7B9l2Y1N9AXQcL/3a7R37I0CgYB0ICJxAPqcKP5WlYFZLiJS/9Gr5UURtOk7DFCWAz/Yzn83aFma7Ala+Li1zEdcydiP7Zir/rvt+Zbrtq1ZyLQe4UiYDMvugcY+Ay+UBPQbi1QEQzBq49OaGVz8PfeeB4zfO2+HVb0ipdoT8+pXLCg5Tycvjr13bGcX3PTWggkDUw=="),
		},
	} {
		key, err := NewFromPrivateDER(test.keyDER)
		if err != nil {
			t.Errorf("%v: failed to load DER-encoded test key: %v", test.name, err)
			continue
		}

		got, err := MarshalPrivateDER(key)
		if err != nil || !bytes.Equal(got, test.keyDER) {
			t.Errorf("%v: MarshalPrivateDER() = (%v, %v), want (%v, nil)", test.name, got, err, test.keyDER)
		}
	}
}

func mustBase64Decode(b64 string) []byte {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic(err)
	}
	return data
}
