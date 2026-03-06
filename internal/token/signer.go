package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// Signer abstracts over signing backends: an in-process ECDSA key, AWS KMS,
// GCP Cloud KMS, HashiCorp Vault Transit, or any other asymmetric signing
// service. Implement this interface and pass it to NewMinterFromSigner to
// keep the private key off-disk.
//
// Sign receives the SHA-256 digest of the JWT signing string and must return
// the signature in IEEE P1363 format (r‖s, each coordinate zero-padded to
// 32 bytes for P-256). AWS KMS and GCP KMS return DER-encoded signatures;
// convert them with DERToP1363 before returning.
type Signer interface {
	Sign(digest []byte) ([]byte, error)
	PublicKey() *ecdsa.PublicKey
}

// ecdsaSigner is the default in-process Signer backed by an ephemeral
// ECDSA P-256 private key. For production use, replace with a KMS-backed
// implementation so the private key never leaves the HSM boundary.
type ecdsaSigner struct {
	key *ecdsa.PrivateKey
}

func newECDSASigner() (*ecdsaSigner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &ecdsaSigner{key: key}, nil
}

func (s *ecdsaSigner) Sign(digest []byte) ([]byte, error) {
	coordLen := (s.key.Curve.Params().BitSize + 7) / 8
	der, err := ecdsa.SignASN1(rand.Reader, s.key, digest)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	return DERToP1363(der, coordLen)
}

func (s *ecdsaSigner) PublicKey() *ecdsa.PublicKey {
	return &s.key.PublicKey
}

// DERToP1363 converts a DER-encoded ECDSA signature to IEEE P1363 format
// (r‖s, each coordinate zero-padded to coordLen bytes).
// JWT ES256 requires P1363; AWS KMS and GCP KMS return DER — use this
// helper inside a KMS Signer implementation to convert before returning.
func DERToP1363(der []byte, coordLen int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("parse DER signature: %w", err)
	}
	out := make([]byte, 2*coordLen)
	sig.R.FillBytes(out[:coordLen])
	sig.S.FillBytes(out[coordLen:])
	return out, nil
}
