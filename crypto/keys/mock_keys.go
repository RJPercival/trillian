// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/google/trillian/crypto/keys (interfaces: SignerFactory)

package keys

import (
	context "context"
	crypto "crypto"
	gomock "github.com/golang/mock/gomock"
	any "github.com/golang/protobuf/ptypes/any"
	trillian "github.com/google/trillian"
	keyspb "github.com/google/trillian/crypto/keyspb"
)

// Mock of SignerFactory interface
type MockSignerFactory struct {
	ctrl     *gomock.Controller
	recorder *_MockSignerFactoryRecorder
}

// Recorder for MockSignerFactory (not exported)
type _MockSignerFactoryRecorder struct {
	mock *MockSignerFactory
}

func NewMockSignerFactory(ctrl *gomock.Controller) *MockSignerFactory {
	mock := &MockSignerFactory{ctrl: ctrl}
	mock.recorder = &_MockSignerFactoryRecorder{mock}
	return mock
}

func (_m *MockSignerFactory) EXPECT() *_MockSignerFactoryRecorder {
	return _m.recorder
}

func (_m *MockSignerFactory) Generate(_param0 context.Context, _param1 *trillian.Tree, _param2 *keyspb.Specification) (*any.Any, error) {
	ret := _m.ctrl.Call(_m, "Generate", _param0, _param1, _param2)
	ret0, _ := ret[0].(*any.Any)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockSignerFactoryRecorder) Generate(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "Generate", arg0, arg1, arg2)
}

func (_m *MockSignerFactory) NewSigner(_param0 context.Context, _param1 *trillian.Tree, _param2 string) (crypto.Signer, error) {
	ret := _m.ctrl.Call(_m, "NewSigner", _param0, _param1, _param2)
	ret0, _ := ret[0].(crypto.Signer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (_mr *_MockSignerFactoryRecorder) NewSigner(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "NewSigner", arg0, arg1, arg2)
}
