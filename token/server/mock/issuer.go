// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	sync "sync"

	token "github.com/chinaso/fabricGM/protos/token"
	server "github.com/chinaso/fabricGM/token/server"
)

type Issuer struct {
	RequestExpectationStub        func(*token.ExpectationRequest) (*token.TokenTransaction, error)
	requestExpectationMutex       sync.RWMutex
	requestExpectationArgsForCall []struct {
		arg1 *token.ExpectationRequest
	}
	requestExpectationReturns struct {
		result1 *token.TokenTransaction
		result2 error
	}
	requestExpectationReturnsOnCall map[int]struct {
		result1 *token.TokenTransaction
		result2 error
	}
	RequestImportStub        func([]*token.TokenToIssue) (*token.TokenTransaction, error)
	requestImportMutex       sync.RWMutex
	requestImportArgsForCall []struct {
		arg1 []*token.TokenToIssue
	}
	requestImportReturns struct {
		result1 *token.TokenTransaction
		result2 error
	}
	requestImportReturnsOnCall map[int]struct {
		result1 *token.TokenTransaction
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Issuer) RequestExpectation(arg1 *token.ExpectationRequest) (*token.TokenTransaction, error) {
	fake.requestExpectationMutex.Lock()
	ret, specificReturn := fake.requestExpectationReturnsOnCall[len(fake.requestExpectationArgsForCall)]
	fake.requestExpectationArgsForCall = append(fake.requestExpectationArgsForCall, struct {
		arg1 *token.ExpectationRequest
	}{arg1})
	fake.recordInvocation("RequestExpectation", []interface{}{arg1})
	fake.requestExpectationMutex.Unlock()
	if fake.RequestExpectationStub != nil {
		return fake.RequestExpectationStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.requestExpectationReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Issuer) RequestExpectationCallCount() int {
	fake.requestExpectationMutex.RLock()
	defer fake.requestExpectationMutex.RUnlock()
	return len(fake.requestExpectationArgsForCall)
}

func (fake *Issuer) RequestExpectationCalls(stub func(*token.ExpectationRequest) (*token.TokenTransaction, error)) {
	fake.requestExpectationMutex.Lock()
	defer fake.requestExpectationMutex.Unlock()
	fake.RequestExpectationStub = stub
}

func (fake *Issuer) RequestExpectationArgsForCall(i int) *token.ExpectationRequest {
	fake.requestExpectationMutex.RLock()
	defer fake.requestExpectationMutex.RUnlock()
	argsForCall := fake.requestExpectationArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Issuer) RequestExpectationReturns(result1 *token.TokenTransaction, result2 error) {
	fake.requestExpectationMutex.Lock()
	defer fake.requestExpectationMutex.Unlock()
	fake.RequestExpectationStub = nil
	fake.requestExpectationReturns = struct {
		result1 *token.TokenTransaction
		result2 error
	}{result1, result2}
}

func (fake *Issuer) RequestExpectationReturnsOnCall(i int, result1 *token.TokenTransaction, result2 error) {
	fake.requestExpectationMutex.Lock()
	defer fake.requestExpectationMutex.Unlock()
	fake.RequestExpectationStub = nil
	if fake.requestExpectationReturnsOnCall == nil {
		fake.requestExpectationReturnsOnCall = make(map[int]struct {
			result1 *token.TokenTransaction
			result2 error
		})
	}
	fake.requestExpectationReturnsOnCall[i] = struct {
		result1 *token.TokenTransaction
		result2 error
	}{result1, result2}
}

func (fake *Issuer) RequestImport(arg1 []*token.TokenToIssue) (*token.TokenTransaction, error) {
	var arg1Copy []*token.TokenToIssue
	if arg1 != nil {
		arg1Copy = make([]*token.TokenToIssue, len(arg1))
		copy(arg1Copy, arg1)
	}
	fake.requestImportMutex.Lock()
	ret, specificReturn := fake.requestImportReturnsOnCall[len(fake.requestImportArgsForCall)]
	fake.requestImportArgsForCall = append(fake.requestImportArgsForCall, struct {
		arg1 []*token.TokenToIssue
	}{arg1Copy})
	fake.recordInvocation("RequestImport", []interface{}{arg1Copy})
	fake.requestImportMutex.Unlock()
	if fake.RequestImportStub != nil {
		return fake.RequestImportStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.requestImportReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Issuer) RequestImportCallCount() int {
	fake.requestImportMutex.RLock()
	defer fake.requestImportMutex.RUnlock()
	return len(fake.requestImportArgsForCall)
}

func (fake *Issuer) RequestImportCalls(stub func([]*token.TokenToIssue) (*token.TokenTransaction, error)) {
	fake.requestImportMutex.Lock()
	defer fake.requestImportMutex.Unlock()
	fake.RequestImportStub = stub
}

func (fake *Issuer) RequestImportArgsForCall(i int) []*token.TokenToIssue {
	fake.requestImportMutex.RLock()
	defer fake.requestImportMutex.RUnlock()
	argsForCall := fake.requestImportArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Issuer) RequestImportReturns(result1 *token.TokenTransaction, result2 error) {
	fake.requestImportMutex.Lock()
	defer fake.requestImportMutex.Unlock()
	fake.RequestImportStub = nil
	fake.requestImportReturns = struct {
		result1 *token.TokenTransaction
		result2 error
	}{result1, result2}
}

func (fake *Issuer) RequestImportReturnsOnCall(i int, result1 *token.TokenTransaction, result2 error) {
	fake.requestImportMutex.Lock()
	defer fake.requestImportMutex.Unlock()
	fake.RequestImportStub = nil
	if fake.requestImportReturnsOnCall == nil {
		fake.requestImportReturnsOnCall = make(map[int]struct {
			result1 *token.TokenTransaction
			result2 error
		})
	}
	fake.requestImportReturnsOnCall[i] = struct {
		result1 *token.TokenTransaction
		result2 error
	}{result1, result2}
}

func (fake *Issuer) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.requestExpectationMutex.RLock()
	defer fake.requestExpectationMutex.RUnlock()
	fake.requestImportMutex.RLock()
	defer fake.requestImportMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Issuer) recordInvocation(key string, args []interface{}) {
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

var _ server.Issuer = new(Issuer)
