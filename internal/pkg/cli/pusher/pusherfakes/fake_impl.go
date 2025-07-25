/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by counterfeiter. DO NOT EDIT.
package pusherfakes

import (
	"sync"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

type FakeImpl struct {
	PushStub        func(map[*v1.Platform]string, string, string, string, map[string]string) error
	pushMutex       sync.RWMutex
	pushArgsForCall []struct {
		arg1 map[*v1.Platform]string
		arg2 string
		arg3 string
		arg4 string
		arg5 map[string]string
	}
	pushReturns struct {
		result1 error
	}
	pushReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeImpl) Push(arg1 map[*v1.Platform]string, arg2 string, arg3 string, arg4 string, arg5 map[string]string) error {
	fake.pushMutex.Lock()
	ret, specificReturn := fake.pushReturnsOnCall[len(fake.pushArgsForCall)]
	fake.pushArgsForCall = append(fake.pushArgsForCall, struct {
		arg1 map[*v1.Platform]string
		arg2 string
		arg3 string
		arg4 string
		arg5 map[string]string
	}{arg1, arg2, arg3, arg4, arg5})
	stub := fake.PushStub
	fakeReturns := fake.pushReturns
	fake.recordInvocation("Push", []interface{}{arg1, arg2, arg3, arg4, arg5})
	fake.pushMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3, arg4, arg5)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *FakeImpl) PushCallCount() int {
	fake.pushMutex.RLock()
	defer fake.pushMutex.RUnlock()
	return len(fake.pushArgsForCall)
}

func (fake *FakeImpl) PushCalls(stub func(map[*v1.Platform]string, string, string, string, map[string]string) error) {
	fake.pushMutex.Lock()
	defer fake.pushMutex.Unlock()
	fake.PushStub = stub
}

func (fake *FakeImpl) PushArgsForCall(i int) (map[*v1.Platform]string, string, string, string, map[string]string) {
	fake.pushMutex.RLock()
	defer fake.pushMutex.RUnlock()
	argsForCall := fake.pushArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3, argsForCall.arg4, argsForCall.arg5
}

func (fake *FakeImpl) PushReturns(result1 error) {
	fake.pushMutex.Lock()
	defer fake.pushMutex.Unlock()
	fake.PushStub = nil
	fake.pushReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeImpl) PushReturnsOnCall(i int, result1 error) {
	fake.pushMutex.Lock()
	defer fake.pushMutex.Unlock()
	fake.PushStub = nil
	if fake.pushReturnsOnCall == nil {
		fake.pushReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.pushReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeImpl) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeImpl) recordInvocation(key string, args []interface{}) {
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
