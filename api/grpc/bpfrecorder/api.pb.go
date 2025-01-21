//
//Copyright 2021 The Kubernetes Authors.
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.3
// 	protoc        v3.21.12
// source: api/grpc/bpfrecorder/api.proto

package api_bpfrecorder

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EmptyRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EmptyRequest) Reset() {
	*x = EmptyRequest{}
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EmptyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EmptyRequest) ProtoMessage() {}

func (x *EmptyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EmptyRequest.ProtoReflect.Descriptor instead.
func (*EmptyRequest) Descriptor() ([]byte, []int) {
	return file_api_grpc_bpfrecorder_api_proto_rawDescGZIP(), []int{0}
}

type EmptyResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EmptyResponse) Reset() {
	*x = EmptyResponse{}
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EmptyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EmptyResponse) ProtoMessage() {}

func (x *EmptyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EmptyResponse.ProtoReflect.Descriptor instead.
func (*EmptyResponse) Descriptor() ([]byte, []int) {
	return file_api_grpc_bpfrecorder_api_proto_rawDescGZIP(), []int{1}
}

type ProfileRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ProfileRequest) Reset() {
	*x = ProfileRequest{}
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ProfileRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProfileRequest) ProtoMessage() {}

func (x *ProfileRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProfileRequest.ProtoReflect.Descriptor instead.
func (*ProfileRequest) Descriptor() ([]byte, []int) {
	return file_api_grpc_bpfrecorder_api_proto_rawDescGZIP(), []int{2}
}

func (x *ProfileRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type SyscallsResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Syscalls      []string               `protobuf:"bytes,1,rep,name=syscalls,proto3" json:"syscalls,omitempty"`
	GoArch        string                 `protobuf:"bytes,2,opt,name=go_arch,json=goArch,proto3" json:"go_arch,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SyscallsResponse) Reset() {
	*x = SyscallsResponse{}
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SyscallsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SyscallsResponse) ProtoMessage() {}

func (x *SyscallsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SyscallsResponse.ProtoReflect.Descriptor instead.
func (*SyscallsResponse) Descriptor() ([]byte, []int) {
	return file_api_grpc_bpfrecorder_api_proto_rawDescGZIP(), []int{3}
}

func (x *SyscallsResponse) GetSyscalls() []string {
	if x != nil {
		return x.Syscalls
	}
	return nil
}

func (x *SyscallsResponse) GetGoArch() string {
	if x != nil {
		return x.GoArch
	}
	return ""
}

type ApparmorResponse struct {
	state         protoimpl.MessageState   `protogen:"open.v1"`
	Files         *ApparmorResponse_Files  `protobuf:"bytes,1,opt,name=files,proto3" json:"files,omitempty"`
	Socket        *ApparmorResponse_Socket `protobuf:"bytes,2,opt,name=socket,proto3" json:"socket,omitempty"`
	Capabilities  []string                 `protobuf:"bytes,3,rep,name=capabilities,proto3" json:"capabilities,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ApparmorResponse) Reset() {
	*x = ApparmorResponse{}
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ApparmorResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApparmorResponse) ProtoMessage() {}

func (x *ApparmorResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApparmorResponse.ProtoReflect.Descriptor instead.
func (*ApparmorResponse) Descriptor() ([]byte, []int) {
	return file_api_grpc_bpfrecorder_api_proto_rawDescGZIP(), []int{4}
}

func (x *ApparmorResponse) GetFiles() *ApparmorResponse_Files {
	if x != nil {
		return x.Files
	}
	return nil
}

func (x *ApparmorResponse) GetSocket() *ApparmorResponse_Socket {
	if x != nil {
		return x.Socket
	}
	return nil
}

func (x *ApparmorResponse) GetCapabilities() []string {
	if x != nil {
		return x.Capabilities
	}
	return nil
}

type ApparmorResponse_Files struct {
	state              protoimpl.MessageState `protogen:"open.v1"`
	AllowedExecutables []string               `protobuf:"bytes,1,rep,name=allowed_executables,json=allowedExecutables,proto3" json:"allowed_executables,omitempty"`
	AllowedLibraries   []string               `protobuf:"bytes,2,rep,name=allowed_libraries,json=allowedLibraries,proto3" json:"allowed_libraries,omitempty"`
	ReadonlyPaths      []string               `protobuf:"bytes,3,rep,name=readonly_paths,json=readonlyPaths,proto3" json:"readonly_paths,omitempty"`
	WriteonlyPaths     []string               `protobuf:"bytes,4,rep,name=writeonly_paths,json=writeonlyPaths,proto3" json:"writeonly_paths,omitempty"`
	ReadwritePaths     []string               `protobuf:"bytes,5,rep,name=readwrite_paths,json=readwritePaths,proto3" json:"readwrite_paths,omitempty"`
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *ApparmorResponse_Files) Reset() {
	*x = ApparmorResponse_Files{}
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ApparmorResponse_Files) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApparmorResponse_Files) ProtoMessage() {}

func (x *ApparmorResponse_Files) ProtoReflect() protoreflect.Message {
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApparmorResponse_Files.ProtoReflect.Descriptor instead.
func (*ApparmorResponse_Files) Descriptor() ([]byte, []int) {
	return file_api_grpc_bpfrecorder_api_proto_rawDescGZIP(), []int{4, 0}
}

func (x *ApparmorResponse_Files) GetAllowedExecutables() []string {
	if x != nil {
		return x.AllowedExecutables
	}
	return nil
}

func (x *ApparmorResponse_Files) GetAllowedLibraries() []string {
	if x != nil {
		return x.AllowedLibraries
	}
	return nil
}

func (x *ApparmorResponse_Files) GetReadonlyPaths() []string {
	if x != nil {
		return x.ReadonlyPaths
	}
	return nil
}

func (x *ApparmorResponse_Files) GetWriteonlyPaths() []string {
	if x != nil {
		return x.WriteonlyPaths
	}
	return nil
}

func (x *ApparmorResponse_Files) GetReadwritePaths() []string {
	if x != nil {
		return x.ReadwritePaths
	}
	return nil
}

type ApparmorResponse_Socket struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	UseRaw        bool                   `protobuf:"varint,1,opt,name=use_raw,json=useRaw,proto3" json:"use_raw,omitempty"`
	UseTcp        bool                   `protobuf:"varint,2,opt,name=use_tcp,json=useTcp,proto3" json:"use_tcp,omitempty"`
	UseUdp        bool                   `protobuf:"varint,3,opt,name=use_udp,json=useUdp,proto3" json:"use_udp,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ApparmorResponse_Socket) Reset() {
	*x = ApparmorResponse_Socket{}
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ApparmorResponse_Socket) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApparmorResponse_Socket) ProtoMessage() {}

func (x *ApparmorResponse_Socket) ProtoReflect() protoreflect.Message {
	mi := &file_api_grpc_bpfrecorder_api_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApparmorResponse_Socket.ProtoReflect.Descriptor instead.
func (*ApparmorResponse_Socket) Descriptor() ([]byte, []int) {
	return file_api_grpc_bpfrecorder_api_proto_rawDescGZIP(), []int{4, 1}
}

func (x *ApparmorResponse_Socket) GetUseRaw() bool {
	if x != nil {
		return x.UseRaw
	}
	return false
}

func (x *ApparmorResponse_Socket) GetUseTcp() bool {
	if x != nil {
		return x.UseTcp
	}
	return false
}

func (x *ApparmorResponse_Socket) GetUseUdp() bool {
	if x != nil {
		return x.UseUdp
	}
	return false
}

var File_api_grpc_bpfrecorder_api_proto protoreflect.FileDescriptor

var file_api_grpc_bpfrecorder_api_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x62, 0x70, 0x66, 0x72, 0x65,
	0x63, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0f, 0x61, 0x70, 0x69, 0x5f, 0x62, 0x70, 0x66, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x65,
	0x72, 0x22, 0x0e, 0x0a, 0x0c, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x22, 0x0f, 0x0a, 0x0d, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x24, 0x0a, 0x0e, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x47, 0x0a, 0x10, 0x53, 0x79, 0x73, 0x63,
	0x61, 0x6c, 0x6c, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1a, 0x0a, 0x08,
	0x73, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08,
	0x73, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x73, 0x12, 0x17, 0x0a, 0x07, 0x67, 0x6f, 0x5f, 0x61,
	0x72, 0x63, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x67, 0x6f, 0x41, 0x72, 0x63,
	0x68, 0x22, 0xed, 0x03, 0x0a, 0x10, 0x41, 0x70, 0x70, 0x61, 0x72, 0x6d, 0x6f, 0x72, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3d, 0x0a, 0x05, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x61, 0x70, 0x69, 0x5f, 0x62, 0x70, 0x66, 0x72,
	0x65, 0x63, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x2e, 0x41, 0x70, 0x70, 0x61, 0x72, 0x6d, 0x6f, 0x72,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x52, 0x05,
	0x66, 0x69, 0x6c, 0x65, 0x73, 0x12, 0x40, 0x0a, 0x06, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x61, 0x70, 0x69, 0x5f, 0x62, 0x70, 0x66, 0x72,
	0x65, 0x63, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x2e, 0x41, 0x70, 0x70, 0x61, 0x72, 0x6d, 0x6f, 0x72,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x52,
	0x06, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x22, 0x0a, 0x0c, 0x63, 0x61, 0x70, 0x61, 0x62,
	0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0c, 0x63,
	0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x1a, 0xde, 0x01, 0x0a, 0x05,
	0x46, 0x69, 0x6c, 0x65, 0x73, 0x12, 0x2f, 0x0a, 0x13, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64,
	0x5f, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x12, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x45, 0x78, 0x65, 0x63, 0x75,
	0x74, 0x61, 0x62, 0x6c, 0x65, 0x73, 0x12, 0x2b, 0x0a, 0x11, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65,
	0x64, 0x5f, 0x6c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x69, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x10, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72,
	0x69, 0x65, 0x73, 0x12, 0x25, 0x0a, 0x0e, 0x72, 0x65, 0x61, 0x64, 0x6f, 0x6e, 0x6c, 0x79, 0x5f,
	0x70, 0x61, 0x74, 0x68, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0d, 0x72, 0x65, 0x61,
	0x64, 0x6f, 0x6e, 0x6c, 0x79, 0x50, 0x61, 0x74, 0x68, 0x73, 0x12, 0x27, 0x0a, 0x0f, 0x77, 0x72,
	0x69, 0x74, 0x65, 0x6f, 0x6e, 0x6c, 0x79, 0x5f, 0x70, 0x61, 0x74, 0x68, 0x73, 0x18, 0x04, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x0e, 0x77, 0x72, 0x69, 0x74, 0x65, 0x6f, 0x6e, 0x6c, 0x79, 0x50, 0x61,
	0x74, 0x68, 0x73, 0x12, 0x27, 0x0a, 0x0f, 0x72, 0x65, 0x61, 0x64, 0x77, 0x72, 0x69, 0x74, 0x65,
	0x5f, 0x70, 0x61, 0x74, 0x68, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0e, 0x72, 0x65,
	0x61, 0x64, 0x77, 0x72, 0x69, 0x74, 0x65, 0x50, 0x61, 0x74, 0x68, 0x73, 0x1a, 0x53, 0x0a, 0x06,
	0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x5f, 0x72, 0x61,
	0x77, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x75, 0x73, 0x65, 0x52, 0x61, 0x77, 0x12,
	0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x5f, 0x74, 0x63, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x06, 0x75, 0x73, 0x65, 0x54, 0x63, 0x70, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x5f,
	0x75, 0x64, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x75, 0x73, 0x65, 0x55, 0x64,
	0x70, 0x32, 0xd8, 0x02, 0x0a, 0x0b, 0x42, 0x70, 0x66, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x65,
	0x72, 0x12, 0x48, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x72, 0x74, 0x12, 0x1d, 0x2e, 0x61, 0x70, 0x69,
	0x5f, 0x62, 0x70, 0x66, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x61, 0x70, 0x69, 0x5f,
	0x62, 0x70, 0x66, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x2e, 0x45, 0x6d, 0x70, 0x74,
	0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x47, 0x0a, 0x04, 0x53,
	0x74, 0x6f, 0x70, 0x12, 0x1d, 0x2e, 0x61, 0x70, 0x69, 0x5f, 0x62, 0x70, 0x66, 0x72, 0x65, 0x63,
	0x6f, 0x72, 0x64, 0x65, 0x72, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x61, 0x70, 0x69, 0x5f, 0x62, 0x70, 0x66, 0x72, 0x65, 0x63, 0x6f,
	0x72, 0x64, 0x65, 0x72, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x00, 0x12, 0x5a, 0x0a, 0x12, 0x53, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x73,
	0x46, 0x6f, 0x72, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x12, 0x1f, 0x2e, 0x61, 0x70, 0x69,
	0x5f, 0x62, 0x70, 0x66, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x2e, 0x50, 0x72, 0x6f,
	0x66, 0x69, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x61, 0x70,
	0x69, 0x5f, 0x62, 0x70, 0x66, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x2e, 0x53, 0x79,
	0x73, 0x63, 0x61, 0x6c, 0x6c, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00,
	0x12, 0x5a, 0x0a, 0x12, 0x41, 0x70, 0x70, 0x61, 0x72, 0x6d, 0x6f, 0x72, 0x46, 0x6f, 0x72, 0x50,
	0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x12, 0x1f, 0x2e, 0x61, 0x70, 0x69, 0x5f, 0x62, 0x70, 0x66,
	0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x2e, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x61, 0x70, 0x69, 0x5f, 0x62, 0x70,
	0x66, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x2e, 0x41, 0x70, 0x70, 0x61, 0x72, 0x6d,
	0x6f, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x12, 0x5a, 0x10,
	0x2f, 0x61, 0x70, 0x69, 0x5f, 0x62, 0x70, 0x66, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x65, 0x72,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_grpc_bpfrecorder_api_proto_rawDescOnce sync.Once
	file_api_grpc_bpfrecorder_api_proto_rawDescData = file_api_grpc_bpfrecorder_api_proto_rawDesc
)

func file_api_grpc_bpfrecorder_api_proto_rawDescGZIP() []byte {
	file_api_grpc_bpfrecorder_api_proto_rawDescOnce.Do(func() {
		file_api_grpc_bpfrecorder_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_grpc_bpfrecorder_api_proto_rawDescData)
	})
	return file_api_grpc_bpfrecorder_api_proto_rawDescData
}

var file_api_grpc_bpfrecorder_api_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_api_grpc_bpfrecorder_api_proto_goTypes = []any{
	(*EmptyRequest)(nil),            // 0: api_bpfrecorder.EmptyRequest
	(*EmptyResponse)(nil),           // 1: api_bpfrecorder.EmptyResponse
	(*ProfileRequest)(nil),          // 2: api_bpfrecorder.ProfileRequest
	(*SyscallsResponse)(nil),        // 3: api_bpfrecorder.SyscallsResponse
	(*ApparmorResponse)(nil),        // 4: api_bpfrecorder.ApparmorResponse
	(*ApparmorResponse_Files)(nil),  // 5: api_bpfrecorder.ApparmorResponse.Files
	(*ApparmorResponse_Socket)(nil), // 6: api_bpfrecorder.ApparmorResponse.Socket
}
var file_api_grpc_bpfrecorder_api_proto_depIdxs = []int32{
	5, // 0: api_bpfrecorder.ApparmorResponse.files:type_name -> api_bpfrecorder.ApparmorResponse.Files
	6, // 1: api_bpfrecorder.ApparmorResponse.socket:type_name -> api_bpfrecorder.ApparmorResponse.Socket
	0, // 2: api_bpfrecorder.BpfRecorder.Start:input_type -> api_bpfrecorder.EmptyRequest
	0, // 3: api_bpfrecorder.BpfRecorder.Stop:input_type -> api_bpfrecorder.EmptyRequest
	2, // 4: api_bpfrecorder.BpfRecorder.SyscallsForProfile:input_type -> api_bpfrecorder.ProfileRequest
	2, // 5: api_bpfrecorder.BpfRecorder.ApparmorForProfile:input_type -> api_bpfrecorder.ProfileRequest
	1, // 6: api_bpfrecorder.BpfRecorder.Start:output_type -> api_bpfrecorder.EmptyResponse
	1, // 7: api_bpfrecorder.BpfRecorder.Stop:output_type -> api_bpfrecorder.EmptyResponse
	3, // 8: api_bpfrecorder.BpfRecorder.SyscallsForProfile:output_type -> api_bpfrecorder.SyscallsResponse
	4, // 9: api_bpfrecorder.BpfRecorder.ApparmorForProfile:output_type -> api_bpfrecorder.ApparmorResponse
	6, // [6:10] is the sub-list for method output_type
	2, // [2:6] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_api_grpc_bpfrecorder_api_proto_init() }
func file_api_grpc_bpfrecorder_api_proto_init() {
	if File_api_grpc_bpfrecorder_api_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_grpc_bpfrecorder_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_grpc_bpfrecorder_api_proto_goTypes,
		DependencyIndexes: file_api_grpc_bpfrecorder_api_proto_depIdxs,
		MessageInfos:      file_api_grpc_bpfrecorder_api_proto_msgTypes,
	}.Build()
	File_api_grpc_bpfrecorder_api_proto = out.File
	file_api_grpc_bpfrecorder_api_proto_rawDesc = nil
	file_api_grpc_bpfrecorder_api_proto_goTypes = nil
	file_api_grpc_bpfrecorder_api_proto_depIdxs = nil
}
