// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	sync "sync"

	chaincode "github.com/chinaso/fabricGM/common/chaincode"
)

type StorePackageProvider struct {
	GetChaincodeInstallPathStub        func() string
	getChaincodeInstallPathMutex       sync.RWMutex
	getChaincodeInstallPathArgsForCall []struct {
	}
	getChaincodeInstallPathReturns struct {
		result1 string
	}
	getChaincodeInstallPathReturnsOnCall map[int]struct {
		result1 string
	}
	ListInstalledChaincodesStub        func() ([]chaincode.InstalledChaincode, error)
	listInstalledChaincodesMutex       sync.RWMutex
	listInstalledChaincodesArgsForCall []struct {
	}
	listInstalledChaincodesReturns struct {
		result1 []chaincode.InstalledChaincode
		result2 error
	}
	listInstalledChaincodesReturnsOnCall map[int]struct {
		result1 []chaincode.InstalledChaincode
		result2 error
	}
	LoadStub        func([]byte) ([]byte, string, string, error)
	loadMutex       sync.RWMutex
	loadArgsForCall []struct {
		arg1 []byte
	}
	loadReturns struct {
		result1 []byte
		result2 string
		result3 string
		result4 error
	}
	loadReturnsOnCall map[int]struct {
		result1 []byte
		result2 string
		result3 string
		result4 error
	}
	RetrieveHashStub        func(string, string) ([]byte, error)
	retrieveHashMutex       sync.RWMutex
	retrieveHashArgsForCall []struct {
		arg1 string
		arg2 string
	}
	retrieveHashReturns struct {
		result1 []byte
		result2 error
	}
	retrieveHashReturnsOnCall map[int]struct {
		result1 []byte
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *StorePackageProvider) GetChaincodeInstallPath() string {
	fake.getChaincodeInstallPathMutex.Lock()
	ret, specificReturn := fake.getChaincodeInstallPathReturnsOnCall[len(fake.getChaincodeInstallPathArgsForCall)]
	fake.getChaincodeInstallPathArgsForCall = append(fake.getChaincodeInstallPathArgsForCall, struct {
	}{})
	fake.recordInvocation("GetChaincodeInstallPath", []interface{}{})
	fake.getChaincodeInstallPathMutex.Unlock()
	if fake.GetChaincodeInstallPathStub != nil {
		return fake.GetChaincodeInstallPathStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.getChaincodeInstallPathReturns
	return fakeReturns.result1
}

func (fake *StorePackageProvider) GetChaincodeInstallPathCallCount() int {
	fake.getChaincodeInstallPathMutex.RLock()
	defer fake.getChaincodeInstallPathMutex.RUnlock()
	return len(fake.getChaincodeInstallPathArgsForCall)
}

func (fake *StorePackageProvider) GetChaincodeInstallPathCalls(stub func() string) {
	fake.getChaincodeInstallPathMutex.Lock()
	defer fake.getChaincodeInstallPathMutex.Unlock()
	fake.GetChaincodeInstallPathStub = stub
}

func (fake *StorePackageProvider) GetChaincodeInstallPathReturns(result1 string) {
	fake.getChaincodeInstallPathMutex.Lock()
	defer fake.getChaincodeInstallPathMutex.Unlock()
	fake.GetChaincodeInstallPathStub = nil
	fake.getChaincodeInstallPathReturns = struct {
		result1 string
	}{result1}
}

func (fake *StorePackageProvider) GetChaincodeInstallPathReturnsOnCall(i int, result1 string) {
	fake.getChaincodeInstallPathMutex.Lock()
	defer fake.getChaincodeInstallPathMutex.Unlock()
	fake.GetChaincodeInstallPathStub = nil
	if fake.getChaincodeInstallPathReturnsOnCall == nil {
		fake.getChaincodeInstallPathReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.getChaincodeInstallPathReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *StorePackageProvider) ListInstalledChaincodes() ([]chaincode.InstalledChaincode, error) {
	fake.listInstalledChaincodesMutex.Lock()
	ret, specificReturn := fake.listInstalledChaincodesReturnsOnCall[len(fake.listInstalledChaincodesArgsForCall)]
	fake.listInstalledChaincodesArgsForCall = append(fake.listInstalledChaincodesArgsForCall, struct {
	}{})
	fake.recordInvocation("ListInstalledChaincodes", []interface{}{})
	fake.listInstalledChaincodesMutex.Unlock()
	if fake.ListInstalledChaincodesStub != nil {
		return fake.ListInstalledChaincodesStub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.listInstalledChaincodesReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *StorePackageProvider) ListInstalledChaincodesCallCount() int {
	fake.listInstalledChaincodesMutex.RLock()
	defer fake.listInstalledChaincodesMutex.RUnlock()
	return len(fake.listInstalledChaincodesArgsForCall)
}

func (fake *StorePackageProvider) ListInstalledChaincodesCalls(stub func() ([]chaincode.InstalledChaincode, error)) {
	fake.listInstalledChaincodesMutex.Lock()
	defer fake.listInstalledChaincodesMutex.Unlock()
	fake.ListInstalledChaincodesStub = stub
}

func (fake *StorePackageProvider) ListInstalledChaincodesReturns(result1 []chaincode.InstalledChaincode, result2 error) {
	fake.listInstalledChaincodesMutex.Lock()
	defer fake.listInstalledChaincodesMutex.Unlock()
	fake.ListInstalledChaincodesStub = nil
	fake.listInstalledChaincodesReturns = struct {
		result1 []chaincode.InstalledChaincode
		result2 error
	}{result1, result2}
}

func (fake *StorePackageProvider) ListInstalledChaincodesReturnsOnCall(i int, result1 []chaincode.InstalledChaincode, result2 error) {
	fake.listInstalledChaincodesMutex.Lock()
	defer fake.listInstalledChaincodesMutex.Unlock()
	fake.ListInstalledChaincodesStub = nil
	if fake.listInstalledChaincodesReturnsOnCall == nil {
		fake.listInstalledChaincodesReturnsOnCall = make(map[int]struct {
			result1 []chaincode.InstalledChaincode
			result2 error
		})
	}
	fake.listInstalledChaincodesReturnsOnCall[i] = struct {
		result1 []chaincode.InstalledChaincode
		result2 error
	}{result1, result2}
}

func (fake *StorePackageProvider) Load(arg1 []byte) ([]byte, string, string, error) {
	var arg1Copy []byte
	if arg1 != nil {
		arg1Copy = make([]byte, len(arg1))
		copy(arg1Copy, arg1)
	}
	fake.loadMutex.Lock()
	ret, specificReturn := fake.loadReturnsOnCall[len(fake.loadArgsForCall)]
	fake.loadArgsForCall = append(fake.loadArgsForCall, struct {
		arg1 []byte
	}{arg1Copy})
	fake.recordInvocation("Load", []interface{}{arg1Copy})
	fake.loadMutex.Unlock()
	if fake.LoadStub != nil {
		return fake.LoadStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3, ret.result4
	}
	fakeReturns := fake.loadReturns
	return fakeReturns.result1, fakeReturns.result2, fakeReturns.result3, fakeReturns.result4
}

func (fake *StorePackageProvider) LoadCallCount() int {
	fake.loadMutex.RLock()
	defer fake.loadMutex.RUnlock()
	return len(fake.loadArgsForCall)
}

func (fake *StorePackageProvider) LoadCalls(stub func([]byte) ([]byte, string, string, error)) {
	fake.loadMutex.Lock()
	defer fake.loadMutex.Unlock()
	fake.LoadStub = stub
}

func (fake *StorePackageProvider) LoadArgsForCall(i int) []byte {
	fake.loadMutex.RLock()
	defer fake.loadMutex.RUnlock()
	argsForCall := fake.loadArgsForCall[i]
	return argsForCall.arg1
}

func (fake *StorePackageProvider) LoadReturns(result1 []byte, result2 string, result3 string, result4 error) {
	fake.loadMutex.Lock()
	defer fake.loadMutex.Unlock()
	fake.LoadStub = nil
	fake.loadReturns = struct {
		result1 []byte
		result2 string
		result3 string
		result4 error
	}{result1, result2, result3, result4}
}

func (fake *StorePackageProvider) LoadReturnsOnCall(i int, result1 []byte, result2 string, result3 string, result4 error) {
	fake.loadMutex.Lock()
	defer fake.loadMutex.Unlock()
	fake.LoadStub = nil
	if fake.loadReturnsOnCall == nil {
		fake.loadReturnsOnCall = make(map[int]struct {
			result1 []byte
			result2 string
			result3 string
			result4 error
		})
	}
	fake.loadReturnsOnCall[i] = struct {
		result1 []byte
		result2 string
		result3 string
		result4 error
	}{result1, result2, result3, result4}
}

func (fake *StorePackageProvider) RetrieveHash(arg1 string, arg2 string) ([]byte, error) {
	fake.retrieveHashMutex.Lock()
	ret, specificReturn := fake.retrieveHashReturnsOnCall[len(fake.retrieveHashArgsForCall)]
	fake.retrieveHashArgsForCall = append(fake.retrieveHashArgsForCall, struct {
		arg1 string
		arg2 string
	}{arg1, arg2})
	fake.recordInvocation("RetrieveHash", []interface{}{arg1, arg2})
	fake.retrieveHashMutex.Unlock()
	if fake.RetrieveHashStub != nil {
		return fake.RetrieveHashStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.retrieveHashReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *StorePackageProvider) RetrieveHashCallCount() int {
	fake.retrieveHashMutex.RLock()
	defer fake.retrieveHashMutex.RUnlock()
	return len(fake.retrieveHashArgsForCall)
}

func (fake *StorePackageProvider) RetrieveHashCalls(stub func(string, string) ([]byte, error)) {
	fake.retrieveHashMutex.Lock()
	defer fake.retrieveHashMutex.Unlock()
	fake.RetrieveHashStub = stub
}

func (fake *StorePackageProvider) RetrieveHashArgsForCall(i int) (string, string) {
	fake.retrieveHashMutex.RLock()
	defer fake.retrieveHashMutex.RUnlock()
	argsForCall := fake.retrieveHashArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *StorePackageProvider) RetrieveHashReturns(result1 []byte, result2 error) {
	fake.retrieveHashMutex.Lock()
	defer fake.retrieveHashMutex.Unlock()
	fake.RetrieveHashStub = nil
	fake.retrieveHashReturns = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *StorePackageProvider) RetrieveHashReturnsOnCall(i int, result1 []byte, result2 error) {
	fake.retrieveHashMutex.Lock()
	defer fake.retrieveHashMutex.Unlock()
	fake.RetrieveHashStub = nil
	if fake.retrieveHashReturnsOnCall == nil {
		fake.retrieveHashReturnsOnCall = make(map[int]struct {
			result1 []byte
			result2 error
		})
	}
	fake.retrieveHashReturnsOnCall[i] = struct {
		result1 []byte
		result2 error
	}{result1, result2}
}

func (fake *StorePackageProvider) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getChaincodeInstallPathMutex.RLock()
	defer fake.getChaincodeInstallPathMutex.RUnlock()
	fake.listInstalledChaincodesMutex.RLock()
	defer fake.listInstalledChaincodesMutex.RUnlock()
	fake.loadMutex.RLock()
	defer fake.loadMutex.RUnlock()
	fake.retrieveHashMutex.RLock()
	defer fake.retrieveHashMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *StorePackageProvider) recordInvocation(key string, args []interface{}) {
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
