package bccsp

import "io"
const (

	SM4="SM4"
)



//SM4KeyGenOpts contains options for SM4 key generation at default security level
type SM4KeyGenOpts struct {
	Temporary bool
}
//Algorithm returns the key generation algorithm identifier (to be used)
func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}
// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM4CBCPKCS7ModeOpts contains options for AES encryption in CBC mode
// with PKCS7 padding.
// Notice that both IV and PRNG can be nil. In that case, the BCCSP implementation
// is supposed to sample the IV using a cryptographic secure PRNG.
// Notice also that either IV or PRNG can be different from nil.
type SM4CBCPKCS7ModeOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}


// HMACTruncated256SM4DeriveKeyOpts contains options for HMAC truncated
// at 256 bits key derivation.
type HMACTruncated256SM4DeriveKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *HMACTruncated256SM4DeriveKeyOpts) Algorithm() string {
	return HMACTruncated256
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *HMACTruncated256SM4DeriveKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// Argument returns the argument to be passed to the HMAC
func (opts *HMACTruncated256SM4DeriveKeyOpts) Argument() []byte {
	return opts.Arg
}


// SM4ImportKeyOpts contains options for importing SM4 256 keys.
type SM4ImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM4ImportKeyOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *SM4ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}
