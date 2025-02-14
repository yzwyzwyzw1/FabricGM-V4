// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	"github.com/chinaso/fabricGM/token/identity"
)

type DeserializerManager struct {
	DeserializerStub        func(channel string) (identity.Deserializer, error)
	deserializerMutex       sync.RWMutex
	deserializerArgsForCall []struct {
		channel string
	}
	deserializerReturns struct {
		result1 identity.Deserializer
		result2 error
	}
	deserializerReturnsOnCall map[int]struct {
		result1 identity.Deserializer
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *DeserializerManager) Deserializer(channel string) (identity.Deserializer, error) {
	fake.deserializerMutex.Lock()
	ret, specificReturn := fake.deserializerReturnsOnCall[len(fake.deserializerArgsForCall)]
	fake.deserializerArgsForCall = append(fake.deserializerArgsForCall, struct {
		channel string
	}{channel})
	fake.recordInvocation("Deserializer", []interface{}{channel})
	fake.deserializerMutex.Unlock()
	if fake.DeserializerStub != nil {
		return fake.DeserializerStub(channel)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.deserializerReturns.result1, fake.deserializerReturns.result2
}

func (fake *DeserializerManager) DeserializerCallCount() int {
	fake.deserializerMutex.RLock()
	defer fake.deserializerMutex.RUnlock()
	return len(fake.deserializerArgsForCall)
}

func (fake *DeserializerManager) DeserializerArgsForCall(i int) string {
	fake.deserializerMutex.RLock()
	defer fake.deserializerMutex.RUnlock()
	return fake.deserializerArgsForCall[i].channel
}

func (fake *DeserializerManager) DeserializerReturns(result1 identity.Deserializer, result2 error) {
	fake.DeserializerStub = nil
	fake.deserializerReturns = struct {
		result1 identity.Deserializer
		result2 error
	}{result1, result2}
}

func (fake *DeserializerManager) DeserializerReturnsOnCall(i int, result1 identity.Deserializer, result2 error) {
	fake.DeserializerStub = nil
	if fake.deserializerReturnsOnCall == nil {
		fake.deserializerReturnsOnCall = make(map[int]struct {
			result1 identity.Deserializer
			result2 error
		})
	}
	fake.deserializerReturnsOnCall[i] = struct {
		result1 identity.Deserializer
		result2 error
	}{result1, result2}
}

func (fake *DeserializerManager) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.deserializerMutex.RLock()
	defer fake.deserializerMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *DeserializerManager) recordInvocation(key string, args []interface{}) {
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

var _ identity.DeserializerManager = new(DeserializerManager)
