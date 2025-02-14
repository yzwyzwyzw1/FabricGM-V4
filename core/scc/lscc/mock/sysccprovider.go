// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	sync "sync"

	channelconfig "github.com/chinaso/fabricGM/common/channelconfig"
	policies "github.com/chinaso/fabricGM/common/policies"
	ledger "github.com/chinaso/fabricGM/core/ledger"
)

type SystemChaincodeProvider struct {
	GetApplicationConfigStub        func(string) (channelconfig.Application, bool)
	getApplicationConfigMutex       sync.RWMutex
	getApplicationConfigArgsForCall []struct {
		arg1 string
	}
	getApplicationConfigReturns struct {
		result1 channelconfig.Application
		result2 bool
	}
	getApplicationConfigReturnsOnCall map[int]struct {
		result1 channelconfig.Application
		result2 bool
	}
	GetQueryExecutorForLedgerStub        func(string) (ledger.QueryExecutor, error)
	getQueryExecutorForLedgerMutex       sync.RWMutex
	getQueryExecutorForLedgerArgsForCall []struct {
		arg1 string
	}
	getQueryExecutorForLedgerReturns struct {
		result1 ledger.QueryExecutor
		result2 error
	}
	getQueryExecutorForLedgerReturnsOnCall map[int]struct {
		result1 ledger.QueryExecutor
		result2 error
	}
	IsSysCCStub        func(string) bool
	isSysCCMutex       sync.RWMutex
	isSysCCArgsForCall []struct {
		arg1 string
	}
	isSysCCReturns struct {
		result1 bool
	}
	isSysCCReturnsOnCall map[int]struct {
		result1 bool
	}
	IsSysCCAndNotInvokableCC2CCStub        func(string) bool
	isSysCCAndNotInvokableCC2CCMutex       sync.RWMutex
	isSysCCAndNotInvokableCC2CCArgsForCall []struct {
		arg1 string
	}
	isSysCCAndNotInvokableCC2CCReturns struct {
		result1 bool
	}
	isSysCCAndNotInvokableCC2CCReturnsOnCall map[int]struct {
		result1 bool
	}
	IsSysCCAndNotInvokableExternalStub        func(string) bool
	isSysCCAndNotInvokableExternalMutex       sync.RWMutex
	isSysCCAndNotInvokableExternalArgsForCall []struct {
		arg1 string
	}
	isSysCCAndNotInvokableExternalReturns struct {
		result1 bool
	}
	isSysCCAndNotInvokableExternalReturnsOnCall map[int]struct {
		result1 bool
	}
	PolicyManagerStub        func(string) (policies.Manager, bool)
	policyManagerMutex       sync.RWMutex
	policyManagerArgsForCall []struct {
		arg1 string
	}
	policyManagerReturns struct {
		result1 policies.Manager
		result2 bool
	}
	policyManagerReturnsOnCall map[int]struct {
		result1 policies.Manager
		result2 bool
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *SystemChaincodeProvider) GetApplicationConfig(arg1 string) (channelconfig.Application, bool) {
	fake.getApplicationConfigMutex.Lock()
	ret, specificReturn := fake.getApplicationConfigReturnsOnCall[len(fake.getApplicationConfigArgsForCall)]
	fake.getApplicationConfigArgsForCall = append(fake.getApplicationConfigArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("GetApplicationConfig", []interface{}{arg1})
	fake.getApplicationConfigMutex.Unlock()
	if fake.GetApplicationConfigStub != nil {
		return fake.GetApplicationConfigStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getApplicationConfigReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *SystemChaincodeProvider) GetApplicationConfigCallCount() int {
	fake.getApplicationConfigMutex.RLock()
	defer fake.getApplicationConfigMutex.RUnlock()
	return len(fake.getApplicationConfigArgsForCall)
}

func (fake *SystemChaincodeProvider) GetApplicationConfigCalls(stub func(string) (channelconfig.Application, bool)) {
	fake.getApplicationConfigMutex.Lock()
	defer fake.getApplicationConfigMutex.Unlock()
	fake.GetApplicationConfigStub = stub
}

func (fake *SystemChaincodeProvider) GetApplicationConfigArgsForCall(i int) string {
	fake.getApplicationConfigMutex.RLock()
	defer fake.getApplicationConfigMutex.RUnlock()
	argsForCall := fake.getApplicationConfigArgsForCall[i]
	return argsForCall.arg1
}

func (fake *SystemChaincodeProvider) GetApplicationConfigReturns(result1 channelconfig.Application, result2 bool) {
	fake.getApplicationConfigMutex.Lock()
	defer fake.getApplicationConfigMutex.Unlock()
	fake.GetApplicationConfigStub = nil
	fake.getApplicationConfigReturns = struct {
		result1 channelconfig.Application
		result2 bool
	}{result1, result2}
}

func (fake *SystemChaincodeProvider) GetApplicationConfigReturnsOnCall(i int, result1 channelconfig.Application, result2 bool) {
	fake.getApplicationConfigMutex.Lock()
	defer fake.getApplicationConfigMutex.Unlock()
	fake.GetApplicationConfigStub = nil
	if fake.getApplicationConfigReturnsOnCall == nil {
		fake.getApplicationConfigReturnsOnCall = make(map[int]struct {
			result1 channelconfig.Application
			result2 bool
		})
	}
	fake.getApplicationConfigReturnsOnCall[i] = struct {
		result1 channelconfig.Application
		result2 bool
	}{result1, result2}
}

func (fake *SystemChaincodeProvider) GetQueryExecutorForLedger(arg1 string) (ledger.QueryExecutor, error) {
	fake.getQueryExecutorForLedgerMutex.Lock()
	ret, specificReturn := fake.getQueryExecutorForLedgerReturnsOnCall[len(fake.getQueryExecutorForLedgerArgsForCall)]
	fake.getQueryExecutorForLedgerArgsForCall = append(fake.getQueryExecutorForLedgerArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("GetQueryExecutorForLedger", []interface{}{arg1})
	fake.getQueryExecutorForLedgerMutex.Unlock()
	if fake.GetQueryExecutorForLedgerStub != nil {
		return fake.GetQueryExecutorForLedgerStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getQueryExecutorForLedgerReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *SystemChaincodeProvider) GetQueryExecutorForLedgerCallCount() int {
	fake.getQueryExecutorForLedgerMutex.RLock()
	defer fake.getQueryExecutorForLedgerMutex.RUnlock()
	return len(fake.getQueryExecutorForLedgerArgsForCall)
}

func (fake *SystemChaincodeProvider) GetQueryExecutorForLedgerCalls(stub func(string) (ledger.QueryExecutor, error)) {
	fake.getQueryExecutorForLedgerMutex.Lock()
	defer fake.getQueryExecutorForLedgerMutex.Unlock()
	fake.GetQueryExecutorForLedgerStub = stub
}

func (fake *SystemChaincodeProvider) GetQueryExecutorForLedgerArgsForCall(i int) string {
	fake.getQueryExecutorForLedgerMutex.RLock()
	defer fake.getQueryExecutorForLedgerMutex.RUnlock()
	argsForCall := fake.getQueryExecutorForLedgerArgsForCall[i]
	return argsForCall.arg1
}

func (fake *SystemChaincodeProvider) GetQueryExecutorForLedgerReturns(result1 ledger.QueryExecutor, result2 error) {
	fake.getQueryExecutorForLedgerMutex.Lock()
	defer fake.getQueryExecutorForLedgerMutex.Unlock()
	fake.GetQueryExecutorForLedgerStub = nil
	fake.getQueryExecutorForLedgerReturns = struct {
		result1 ledger.QueryExecutor
		result2 error
	}{result1, result2}
}

func (fake *SystemChaincodeProvider) GetQueryExecutorForLedgerReturnsOnCall(i int, result1 ledger.QueryExecutor, result2 error) {
	fake.getQueryExecutorForLedgerMutex.Lock()
	defer fake.getQueryExecutorForLedgerMutex.Unlock()
	fake.GetQueryExecutorForLedgerStub = nil
	if fake.getQueryExecutorForLedgerReturnsOnCall == nil {
		fake.getQueryExecutorForLedgerReturnsOnCall = make(map[int]struct {
			result1 ledger.QueryExecutor
			result2 error
		})
	}
	fake.getQueryExecutorForLedgerReturnsOnCall[i] = struct {
		result1 ledger.QueryExecutor
		result2 error
	}{result1, result2}
}

func (fake *SystemChaincodeProvider) IsSysCC(arg1 string) bool {
	fake.isSysCCMutex.Lock()
	ret, specificReturn := fake.isSysCCReturnsOnCall[len(fake.isSysCCArgsForCall)]
	fake.isSysCCArgsForCall = append(fake.isSysCCArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("IsSysCC", []interface{}{arg1})
	fake.isSysCCMutex.Unlock()
	if fake.IsSysCCStub != nil {
		return fake.IsSysCCStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.isSysCCReturns
	return fakeReturns.result1
}

func (fake *SystemChaincodeProvider) IsSysCCCallCount() int {
	fake.isSysCCMutex.RLock()
	defer fake.isSysCCMutex.RUnlock()
	return len(fake.isSysCCArgsForCall)
}

func (fake *SystemChaincodeProvider) IsSysCCCalls(stub func(string) bool) {
	fake.isSysCCMutex.Lock()
	defer fake.isSysCCMutex.Unlock()
	fake.IsSysCCStub = stub
}

func (fake *SystemChaincodeProvider) IsSysCCArgsForCall(i int) string {
	fake.isSysCCMutex.RLock()
	defer fake.isSysCCMutex.RUnlock()
	argsForCall := fake.isSysCCArgsForCall[i]
	return argsForCall.arg1
}

func (fake *SystemChaincodeProvider) IsSysCCReturns(result1 bool) {
	fake.isSysCCMutex.Lock()
	defer fake.isSysCCMutex.Unlock()
	fake.IsSysCCStub = nil
	fake.isSysCCReturns = struct {
		result1 bool
	}{result1}
}

func (fake *SystemChaincodeProvider) IsSysCCReturnsOnCall(i int, result1 bool) {
	fake.isSysCCMutex.Lock()
	defer fake.isSysCCMutex.Unlock()
	fake.IsSysCCStub = nil
	if fake.isSysCCReturnsOnCall == nil {
		fake.isSysCCReturnsOnCall = make(map[int]struct {
			result1 bool
		})
	}
	fake.isSysCCReturnsOnCall[i] = struct {
		result1 bool
	}{result1}
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableCC2CC(arg1 string) bool {
	fake.isSysCCAndNotInvokableCC2CCMutex.Lock()
	ret, specificReturn := fake.isSysCCAndNotInvokableCC2CCReturnsOnCall[len(fake.isSysCCAndNotInvokableCC2CCArgsForCall)]
	fake.isSysCCAndNotInvokableCC2CCArgsForCall = append(fake.isSysCCAndNotInvokableCC2CCArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("IsSysCCAndNotInvokableCC2CC", []interface{}{arg1})
	fake.isSysCCAndNotInvokableCC2CCMutex.Unlock()
	if fake.IsSysCCAndNotInvokableCC2CCStub != nil {
		return fake.IsSysCCAndNotInvokableCC2CCStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.isSysCCAndNotInvokableCC2CCReturns
	return fakeReturns.result1
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableCC2CCCallCount() int {
	fake.isSysCCAndNotInvokableCC2CCMutex.RLock()
	defer fake.isSysCCAndNotInvokableCC2CCMutex.RUnlock()
	return len(fake.isSysCCAndNotInvokableCC2CCArgsForCall)
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableCC2CCCalls(stub func(string) bool) {
	fake.isSysCCAndNotInvokableCC2CCMutex.Lock()
	defer fake.isSysCCAndNotInvokableCC2CCMutex.Unlock()
	fake.IsSysCCAndNotInvokableCC2CCStub = stub
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableCC2CCArgsForCall(i int) string {
	fake.isSysCCAndNotInvokableCC2CCMutex.RLock()
	defer fake.isSysCCAndNotInvokableCC2CCMutex.RUnlock()
	argsForCall := fake.isSysCCAndNotInvokableCC2CCArgsForCall[i]
	return argsForCall.arg1
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableCC2CCReturns(result1 bool) {
	fake.isSysCCAndNotInvokableCC2CCMutex.Lock()
	defer fake.isSysCCAndNotInvokableCC2CCMutex.Unlock()
	fake.IsSysCCAndNotInvokableCC2CCStub = nil
	fake.isSysCCAndNotInvokableCC2CCReturns = struct {
		result1 bool
	}{result1}
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableCC2CCReturnsOnCall(i int, result1 bool) {
	fake.isSysCCAndNotInvokableCC2CCMutex.Lock()
	defer fake.isSysCCAndNotInvokableCC2CCMutex.Unlock()
	fake.IsSysCCAndNotInvokableCC2CCStub = nil
	if fake.isSysCCAndNotInvokableCC2CCReturnsOnCall == nil {
		fake.isSysCCAndNotInvokableCC2CCReturnsOnCall = make(map[int]struct {
			result1 bool
		})
	}
	fake.isSysCCAndNotInvokableCC2CCReturnsOnCall[i] = struct {
		result1 bool
	}{result1}
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableExternal(arg1 string) bool {
	fake.isSysCCAndNotInvokableExternalMutex.Lock()
	ret, specificReturn := fake.isSysCCAndNotInvokableExternalReturnsOnCall[len(fake.isSysCCAndNotInvokableExternalArgsForCall)]
	fake.isSysCCAndNotInvokableExternalArgsForCall = append(fake.isSysCCAndNotInvokableExternalArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("IsSysCCAndNotInvokableExternal", []interface{}{arg1})
	fake.isSysCCAndNotInvokableExternalMutex.Unlock()
	if fake.IsSysCCAndNotInvokableExternalStub != nil {
		return fake.IsSysCCAndNotInvokableExternalStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.isSysCCAndNotInvokableExternalReturns
	return fakeReturns.result1
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableExternalCallCount() int {
	fake.isSysCCAndNotInvokableExternalMutex.RLock()
	defer fake.isSysCCAndNotInvokableExternalMutex.RUnlock()
	return len(fake.isSysCCAndNotInvokableExternalArgsForCall)
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableExternalCalls(stub func(string) bool) {
	fake.isSysCCAndNotInvokableExternalMutex.Lock()
	defer fake.isSysCCAndNotInvokableExternalMutex.Unlock()
	fake.IsSysCCAndNotInvokableExternalStub = stub
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableExternalArgsForCall(i int) string {
	fake.isSysCCAndNotInvokableExternalMutex.RLock()
	defer fake.isSysCCAndNotInvokableExternalMutex.RUnlock()
	argsForCall := fake.isSysCCAndNotInvokableExternalArgsForCall[i]
	return argsForCall.arg1
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableExternalReturns(result1 bool) {
	fake.isSysCCAndNotInvokableExternalMutex.Lock()
	defer fake.isSysCCAndNotInvokableExternalMutex.Unlock()
	fake.IsSysCCAndNotInvokableExternalStub = nil
	fake.isSysCCAndNotInvokableExternalReturns = struct {
		result1 bool
	}{result1}
}

func (fake *SystemChaincodeProvider) IsSysCCAndNotInvokableExternalReturnsOnCall(i int, result1 bool) {
	fake.isSysCCAndNotInvokableExternalMutex.Lock()
	defer fake.isSysCCAndNotInvokableExternalMutex.Unlock()
	fake.IsSysCCAndNotInvokableExternalStub = nil
	if fake.isSysCCAndNotInvokableExternalReturnsOnCall == nil {
		fake.isSysCCAndNotInvokableExternalReturnsOnCall = make(map[int]struct {
			result1 bool
		})
	}
	fake.isSysCCAndNotInvokableExternalReturnsOnCall[i] = struct {
		result1 bool
	}{result1}
}

func (fake *SystemChaincodeProvider) PolicyManager(arg1 string) (policies.Manager, bool) {
	fake.policyManagerMutex.Lock()
	ret, specificReturn := fake.policyManagerReturnsOnCall[len(fake.policyManagerArgsForCall)]
	fake.policyManagerArgsForCall = append(fake.policyManagerArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("PolicyManager", []interface{}{arg1})
	fake.policyManagerMutex.Unlock()
	if fake.PolicyManagerStub != nil {
		return fake.PolicyManagerStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.policyManagerReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *SystemChaincodeProvider) PolicyManagerCallCount() int {
	fake.policyManagerMutex.RLock()
	defer fake.policyManagerMutex.RUnlock()
	return len(fake.policyManagerArgsForCall)
}

func (fake *SystemChaincodeProvider) PolicyManagerCalls(stub func(string) (policies.Manager, bool)) {
	fake.policyManagerMutex.Lock()
	defer fake.policyManagerMutex.Unlock()
	fake.PolicyManagerStub = stub
}

func (fake *SystemChaincodeProvider) PolicyManagerArgsForCall(i int) string {
	fake.policyManagerMutex.RLock()
	defer fake.policyManagerMutex.RUnlock()
	argsForCall := fake.policyManagerArgsForCall[i]
	return argsForCall.arg1
}

func (fake *SystemChaincodeProvider) PolicyManagerReturns(result1 policies.Manager, result2 bool) {
	fake.policyManagerMutex.Lock()
	defer fake.policyManagerMutex.Unlock()
	fake.PolicyManagerStub = nil
	fake.policyManagerReturns = struct {
		result1 policies.Manager
		result2 bool
	}{result1, result2}
}

func (fake *SystemChaincodeProvider) PolicyManagerReturnsOnCall(i int, result1 policies.Manager, result2 bool) {
	fake.policyManagerMutex.Lock()
	defer fake.policyManagerMutex.Unlock()
	fake.PolicyManagerStub = nil
	if fake.policyManagerReturnsOnCall == nil {
		fake.policyManagerReturnsOnCall = make(map[int]struct {
			result1 policies.Manager
			result2 bool
		})
	}
	fake.policyManagerReturnsOnCall[i] = struct {
		result1 policies.Manager
		result2 bool
	}{result1, result2}
}

func (fake *SystemChaincodeProvider) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getApplicationConfigMutex.RLock()
	defer fake.getApplicationConfigMutex.RUnlock()
	fake.getQueryExecutorForLedgerMutex.RLock()
	defer fake.getQueryExecutorForLedgerMutex.RUnlock()
	fake.isSysCCMutex.RLock()
	defer fake.isSysCCMutex.RUnlock()
	fake.isSysCCAndNotInvokableCC2CCMutex.RLock()
	defer fake.isSysCCAndNotInvokableCC2CCMutex.RUnlock()
	fake.isSysCCAndNotInvokableExternalMutex.RLock()
	defer fake.isSysCCAndNotInvokableExternalMutex.RUnlock()
	fake.policyManagerMutex.RLock()
	defer fake.policyManagerMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *SystemChaincodeProvider) recordInvocation(key string, args []interface{}) {
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
