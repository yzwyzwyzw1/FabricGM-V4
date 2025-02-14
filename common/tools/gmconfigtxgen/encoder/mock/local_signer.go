// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	cb "github.com/chinaso/fabricGM/protos/common"
)

type LocalSigner struct {
	NewSignatureHeaderStub        func() (*cb.SignatureHeader, error)
	newSignatureHeaderMutex       sync.RWMutex
	newSignatureHeaderArgsForCall []struct{}
	newSignatureHeaderReturns     struct {
		result1 *cb.SignatureHeader
		result2 error
	}
	newSignatureHeaderReturnsOnCall map[int]struct {
		result1 *cb.SignatureHeader
		result2 error
	}
	SignStub        func(message []byte) ([]byte, error)
	signMutex       sync.RWMutex
	signArgsForCall []struct {
		message []byte
	}
	signReturns struct {
		result1 []byte
		result2 error
	}
	signReturnsOnCall map[int]struct {
		result1 []byte
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *LocalSigner) NewSignatureHeader() (*cb.SignatureHeader, error) {
	fake.newSignatureHeaderMutex.Lock()
	ret, specificReturn := fake.newSignatureHeaderReturnsOnCall[len(fake.newSignatureHeaderArgsForCall)]
	fake.newSignatureHeaderArgsForCall = append(fake.newSignatureHeaderArgsForCall, struct{}{})
	fake.recordInvocation("NewSignatureHeader", []interface{}{})
	fake.newSignatureHeaderMutex.Unlock()
	if fake.NewSignatureHeaderStub != nil {
		return fake.NewSignatureHeaderStub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.newSignatureHeaderReturns.result1, fake.newSignatureHeaderReturns.result2
}

func (fake *LocalSigner) NewSignatureHeaderCallCount() int {
	fake.newSignatureHeaderMutex.RLock()
	defer fake.newSignatureHeaderMutex.RUnlock()
	return len(fake.newSignatureHeaderArgsForCall)
}

func (fake *LocalSigner) NewSignatureHeaderReturns(result1 *cb.SignatureHeader, result2 error) {
	fake.NewSignatureHeaderStub = nil
	fake.newSignatureHeaderReturns = struct {
		result1 *cb.SignatureHeader
		result2 error
	}{result1, result2}
}

func (fake *LocalSigner) NewSignatureHeaderReturnsOnCall(i int, result1 *cb.SignatureHeader, result2 error) {
	fake.NewSignatureHeaderStub = nil
	if fake.newSignatureHeaderReturnsOnCall == nil {
		fake.newSignatureHeaderReturnsOnCall = make(map[int]struct {
			result1 *cb.SignatureHeader
			result2 error
		})
	}
	fake.newSignatureHeaderReturnsOnCall[i] = struct {
		result1 *cb.SignatureHeader
		result2 error
	}{result1, result2}
}

func (fake *LocalSigner) Sign(message []byte) ([]byte, error) {
	var messageCopy []byte
	if message != nil {
		messageCopy = make([]byte, len(message))
		copy(messageCopy, message)
	}
	fake.signMutex.Lock()
	ret, specificReturn := fake.signReturnsOnCall[len(fake.signArgsForCall)]
	fake.signArgsForCall = append(fake.signArgsForCall, struct {
		message []byte
	}{messageCopy})
	fake.recordInvocation("Sign", []interface{}{messageCopy})
	fake.signMutex.Unlock()
	if fake.SignStub != nil {
		return fake.SignStub(message)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.signReturns.result1, fake.signReturns.result2
}

func (fake *LocalSigner) SignCallCount() int {
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	return len(fake.signArgsForCall)
}

func (fake *LocalSigner) SignArgsForCall(i int) []byte {
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	return fake.signArgsForCall[i].message
}

func (fake *LocalSigner) SignReturns(result1 []byte, result2 error) {
	fake.SignStub = nil
	fake.signReturns = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *LocalSigner) SignReturnsOnCall(i int, result1 []byte, result2 error) {
	fake.SignStub = nil
	if fake.signReturnsOnCall == nil {
		fake.signReturnsOnCall = make(map[int]struct {
			result1 []byte
			result2 error
		})
	}
	fake.signReturnsOnCall[i] = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *LocalSigner) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.newSignatureHeaderMutex.RLock()
	defer fake.newSignatureHeaderMutex.RUnlock()
	fake.signMutex.RLock()
	defer fake.signMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *LocalSigner) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}
