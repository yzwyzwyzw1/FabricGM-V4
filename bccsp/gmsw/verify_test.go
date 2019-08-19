package gmsw

import (
	"errors"
	"github.com/stretchr/testify/assert"
	mocks2 "github.com/chinaso/fabricGM/bccsp/mocks"
	"github.com/chinaso/fabricGM/bccsp/gmsw/mocks"

	"reflect"
	"testing"
)

func TestVerify(t *testing.T) {
	t.Parallel()

	expectedKey := &mocks2.MockKey{}
	expectetSignature := []byte{1, 2, 3, 4, 5}
	expectetDigest := []byte{1, 2, 3, 4}
	expectedOpts := &mocks2.SignerOpts{}
	expectetValue := true
	expectedErr := errors.New("Expected Error")

	verifiers := make(map[reflect.Type]Verifier)
	verifiers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.Verifier{
		KeyArg:       expectedKey,
		SignatureArg: expectetSignature,
		DigestArg:    expectetDigest,
		OptsArg:      expectedOpts,
		Value:        expectetValue,
		Err:          nil,
	}
	csp := CSP{Verifiers: verifiers}
	value, err := csp.Verify(expectedKey, expectetSignature, expectetDigest, expectedOpts)
	assert.Equal(t, expectetValue, value)
	assert.Nil(t, err)

	verifiers = make(map[reflect.Type]Verifier)
	verifiers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.Verifier{
		KeyArg:       expectedKey,
		SignatureArg: expectetSignature,
		DigestArg:    expectetDigest,
		OptsArg:      expectedOpts,
		Value:        false,
		Err:          expectedErr,
	}
	csp = CSP{Verifiers: verifiers}
	value, err = csp.Verify(expectedKey, expectetSignature, expectetDigest, expectedOpts)
	assert.False(t, value)
	assert.Contains(t, err.Error(), expectedErr.Error())
}

