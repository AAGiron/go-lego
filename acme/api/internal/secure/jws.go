package secure

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/liboqs_sig"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/go-acme/lego/v4/acme/api/internal/nonces"
	jose "gopkg.in/square/go-jose.v2"
)

// JWS Represents a JWS.
type JWS struct {
	privKey crypto.PrivateKey
	kid     string // Key identifier
	nonces  *nonces.Manager
}

// NewJWS Create a new JWS.
func NewJWS(privateKey crypto.PrivateKey, kid string, nonceManager *nonces.Manager) *JWS {
	return &JWS{
		privKey: privateKey,
		nonces:  nonceManager,
		kid:     kid,
	}
}

// SetKid Sets a key identifier.
func (j *JWS) SetKid(kid string) {
	j.kid = kid
}

// SignContent Signs a content with the JWS.
func (j *JWS) SignContent(url string, content []byte) (*jose.JSONWebSignature, error) {
	var alg jose.SignatureAlgorithm
	switch k := j.privKey.(type) {
	case *rsa.PrivateKey:
		alg = jose.RS256
	case *ecdsa.PrivateKey:
		if k.Curve == elliptic.P256() {
			alg = jose.ES256
		} else if k.Curve == elliptic.P384() {
			alg = jose.ES384
		}
	case *liboqs_sig.PrivateKey:
		switch k.SigId {
		case liboqs_sig.Dilithium2:
			alg = jose.Dilithium2
		case liboqs_sig.Dilithium3:
			alg = jose.Dilithium3
		case liboqs_sig.Dilithium5:
			alg = jose.Dilithium5
		case liboqs_sig.Falcon512:
			alg = jose.Falcon512
		case liboqs_sig.Falcon1024:
			alg = jose.Falcon1024
		case liboqs_sig.SphincsShake128sSimple:
			alg = jose.SphincsShake128sSimple
		case liboqs_sig.SphincsShake256sSimple:
			alg = jose.SphincsShake256sSimple
		case liboqs_sig.P256_Dilithium2:
			alg = jose.P256_Dilithium2
		case liboqs_sig.P256_Falcon512:
			alg = jose.P256_Falcon512
		case liboqs_sig.P256_SphincsShake128sSimple:
			alg = jose.P256_SphincsShake128sSimple
		case liboqs_sig.P384_Dilithium3:
			alg = jose.P384_Dilithium3
		case liboqs_sig.P521_Dilithium5:
			alg = jose.P521_Dilithium5
		case liboqs_sig.P521_Falcon1024:
			alg = jose.P521_Falcon1024
		case liboqs_sig.P521_SphincsShake256sSimple:
			alg = jose.P521_SphincsShake256sSimple
		}
	}

	signKey := jose.SigningKey{
		Algorithm: alg,
		Key:       jose.JSONWebKey{Key: j.privKey, KeyID: j.kid},
	}

	options := jose.SignerOptions{
		NonceSource: j.nonces,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	if j.kid == "" {
		options.EmbedJWK = true
	}

	signer, err := jose.NewSigner(signKey, &options)
	if err != nil {
		return nil, fmt.Errorf("failed to create jose signer: %w", err)
	}

	signed, err := signer.Sign(content)
	if err != nil {
		return nil, fmt.Errorf("failed to sign content: %w", err)
	}
	return signed, nil
}

// SignEABContent Signs an external account binding content with the JWS.
func (j *JWS) SignEABContent(url, kid string, hmac []byte) (*jose.JSONWebSignature, error) {
	jwk := jose.JSONWebKey{Key: j.privKey}
	jwkJSON, err := jwk.Public().MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("acme: error encoding eab jwk key: %w", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: hmac},
		&jose.SignerOptions{
			EmbedJWK: false,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": kid,
				"url": url,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create External Account Binding jose signer: %w", err)
	}

	signed, err := signer.Sign(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to External Account Binding sign content: %w", err)
	}

	return signed, nil
}

// GetKeyAuthorization Gets the key authorization for a token.
func (j *JWS) GetKeyAuthorization(token string) (string, error) {
	var publicKey crypto.PublicKey
	switch k := j.privKey.(type) {
	case *ecdsa.PrivateKey:
		publicKey = k.Public()
	case *rsa.PrivateKey:
		publicKey = k.Public()
	case liboqs_sig.PrivateKey:
		publicKey = k.Public()
	case *liboqs_sig.PrivateKey:
		publicKey = k.Public()
	}

	// Generate the Key Authorization for the challenge
	jwk := &jose.JSONWebKey{Key: publicKey}

	thumbBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	// unpad the base64URL
	keyThumb := base64.RawURLEncoding.EncodeToString(thumbBytes)

	return token + "." + keyThumb, nil
}
