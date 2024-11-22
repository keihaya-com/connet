// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v5.28.2
// source: shared.proto

package pb

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

type Error_Code int32

const (
	// Generic
	Error_Unknown        Error_Code = 0
	Error_RequestUnknown Error_Code = 1
	// Authentication
	Error_AuthenticationFailed Error_Code = 100
	// Register codes
	Error_RegistrationFailed Error_Code = 200
	// Server connect codes
	Error_ListenerNotFound       Error_Code = 300
	Error_ListenerNotConnected   Error_Code = 301
	Error_ListenerRequestFailed  Error_Code = 302
	Error_ListenerResponseFailed Error_Code = 303
	// Client connect codes
	Error_DestinationNotFound   Error_Code = 400
	Error_DestinationDialFailed Error_Code = 401
)

// Enum value maps for Error_Code.
var (
	Error_Code_name = map[int32]string{
		0:   "Unknown",
		1:   "RequestUnknown",
		100: "AuthenticationFailed",
		200: "RegistrationFailed",
		300: "ListenerNotFound",
		301: "ListenerNotConnected",
		302: "ListenerRequestFailed",
		303: "ListenerResponseFailed",
		400: "DestinationNotFound",
		401: "DestinationDialFailed",
	}
	Error_Code_value = map[string]int32{
		"Unknown":                0,
		"RequestUnknown":         1,
		"AuthenticationFailed":   100,
		"RegistrationFailed":     200,
		"ListenerNotFound":       300,
		"ListenerNotConnected":   301,
		"ListenerRequestFailed":  302,
		"ListenerResponseFailed": 303,
		"DestinationNotFound":    400,
		"DestinationDialFailed":  401,
	}
)

func (x Error_Code) Enum() *Error_Code {
	p := new(Error_Code)
	*p = x
	return p
}

func (x Error_Code) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Error_Code) Descriptor() protoreflect.EnumDescriptor {
	return file_shared_proto_enumTypes[0].Descriptor()
}

func (Error_Code) Type() protoreflect.EnumType {
	return &file_shared_proto_enumTypes[0]
}

func (x Error_Code) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Error_Code.Descriptor instead.
func (Error_Code) EnumDescriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{3, 0}
}

type Addr struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	V4 []byte `protobuf:"bytes,1,opt,name=v4,proto3" json:"v4,omitempty"`
	V6 []byte `protobuf:"bytes,2,opt,name=v6,proto3" json:"v6,omitempty"`
}

func (x *Addr) Reset() {
	*x = Addr{}
	mi := &file_shared_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Addr) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Addr) ProtoMessage() {}

func (x *Addr) ProtoReflect() protoreflect.Message {
	mi := &file_shared_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Addr.ProtoReflect.Descriptor instead.
func (*Addr) Descriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{0}
}

func (x *Addr) GetV4() []byte {
	if x != nil {
		return x.V4
	}
	return nil
}

func (x *Addr) GetV6() []byte {
	if x != nil {
		return x.V6
	}
	return nil
}

type AddrPort struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Addr *Addr  `protobuf:"bytes,1,opt,name=addr,proto3" json:"addr,omitempty"`
	Port uint32 `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"` // really uint16, but not a thing in protobuf
}

func (x *AddrPort) Reset() {
	*x = AddrPort{}
	mi := &file_shared_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AddrPort) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddrPort) ProtoMessage() {}

func (x *AddrPort) ProtoReflect() protoreflect.Message {
	mi := &file_shared_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddrPort.ProtoReflect.Descriptor instead.
func (*AddrPort) Descriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{1}
}

func (x *AddrPort) GetAddr() *Addr {
	if x != nil {
		return x.Addr
	}
	return nil
}

func (x *AddrPort) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

type Binding struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Realm string `protobuf:"bytes,2,opt,name=realm,proto3" json:"realm,omitempty"`
}

func (x *Binding) Reset() {
	*x = Binding{}
	mi := &file_shared_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Binding) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Binding) ProtoMessage() {}

func (x *Binding) ProtoReflect() protoreflect.Message {
	mi := &file_shared_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Binding.ProtoReflect.Descriptor instead.
func (*Binding) Descriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{2}
}

func (x *Binding) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Binding) GetRealm() string {
	if x != nil {
		return x.Realm
	}
	return ""
}

type Error struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code    Error_Code `protobuf:"varint,1,opt,name=code,proto3,enum=shared.Error_Code" json:"code,omitempty"`
	Message string     `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *Error) Reset() {
	*x = Error{}
	mi := &file_shared_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Error) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Error) ProtoMessage() {}

func (x *Error) ProtoReflect() protoreflect.Message {
	mi := &file_shared_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Error.ProtoReflect.Descriptor instead.
func (*Error) Descriptor() ([]byte, []int) {
	return file_shared_proto_rawDescGZIP(), []int{3}
}

func (x *Error) GetCode() Error_Code {
	if x != nil {
		return x.Code
	}
	return Error_Unknown
}

func (x *Error) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_shared_proto protoreflect.FileDescriptor

var file_shared_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06,
	0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x22, 0x26, 0x0a, 0x04, 0x41, 0x64, 0x64, 0x72, 0x12, 0x0e,
	0x0a, 0x02, 0x76, 0x34, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x76, 0x34, 0x12, 0x0e,
	0x0a, 0x02, 0x76, 0x36, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x76, 0x36, 0x22, 0x40,
	0x0a, 0x08, 0x41, 0x64, 0x64, 0x72, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x20, 0x0a, 0x04, 0x61, 0x64,
	0x64, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x73, 0x68, 0x61, 0x72, 0x65,
	0x64, 0x2e, 0x41, 0x64, 0x64, 0x72, 0x52, 0x04, 0x61, 0x64, 0x64, 0x72, 0x12, 0x12, 0x0a, 0x04,
	0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74,
	0x22, 0x33, 0x0a, 0x07, 0x42, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x14, 0x0a, 0x05, 0x72, 0x65, 0x61, 0x6c, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x72, 0x65, 0x61, 0x6c, 0x6d, 0x22, 0xc7, 0x02, 0x0a, 0x05, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12,
	0x26, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x12, 0x2e,
	0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x2e, 0x43, 0x6f, 0x64,
	0x65, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x22, 0xfb, 0x01, 0x0a, 0x04, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x6e,
	0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x10, 0x00, 0x12, 0x12, 0x0a, 0x0e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x10, 0x01, 0x12, 0x18, 0x0a, 0x14, 0x41,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x46, 0x61, 0x69,
	0x6c, 0x65, 0x64, 0x10, 0x64, 0x12, 0x17, 0x0a, 0x12, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x10, 0xc8, 0x01, 0x12, 0x15,
	0x0a, 0x10, 0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x4e, 0x6f, 0x74, 0x46, 0x6f, 0x75,
	0x6e, 0x64, 0x10, 0xac, 0x02, 0x12, 0x19, 0x0a, 0x14, 0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65,
	0x72, 0x4e, 0x6f, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65, 0x64, 0x10, 0xad, 0x02,
	0x12, 0x1a, 0x0a, 0x15, 0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x10, 0xae, 0x02, 0x12, 0x1b, 0x0a, 0x16,
	0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x10, 0xaf, 0x02, 0x12, 0x18, 0x0a, 0x13, 0x44, 0x65, 0x73,
	0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4e, 0x6f, 0x74, 0x46, 0x6f, 0x75, 0x6e, 0x64,
	0x10, 0x90, 0x03, 0x12, 0x1a, 0x0a, 0x15, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x44, 0x69, 0x61, 0x6c, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x10, 0x91, 0x03, 0x42,
	0x22, 0x5a, 0x20, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6b, 0x65,
	0x69, 0x68, 0x61, 0x79, 0x61, 0x2d, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x74,
	0x2f, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_shared_proto_rawDescOnce sync.Once
	file_shared_proto_rawDescData = file_shared_proto_rawDesc
)

func file_shared_proto_rawDescGZIP() []byte {
	file_shared_proto_rawDescOnce.Do(func() {
		file_shared_proto_rawDescData = protoimpl.X.CompressGZIP(file_shared_proto_rawDescData)
	})
	return file_shared_proto_rawDescData
}

var file_shared_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_shared_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_shared_proto_goTypes = []any{
	(Error_Code)(0),  // 0: shared.Error.Code
	(*Addr)(nil),     // 1: shared.Addr
	(*AddrPort)(nil), // 2: shared.AddrPort
	(*Binding)(nil),  // 3: shared.Binding
	(*Error)(nil),    // 4: shared.Error
}
var file_shared_proto_depIdxs = []int32{
	1, // 0: shared.AddrPort.addr:type_name -> shared.Addr
	0, // 1: shared.Error.code:type_name -> shared.Error.Code
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_shared_proto_init() }
func file_shared_proto_init() {
	if File_shared_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_shared_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_shared_proto_goTypes,
		DependencyIndexes: file_shared_proto_depIdxs,
		EnumInfos:         file_shared_proto_enumTypes,
		MessageInfos:      file_shared_proto_msgTypes,
	}.Build()
	File_shared_proto = out.File
	file_shared_proto_rawDesc = nil
	file_shared_proto_goTypes = nil
	file_shared_proto_depIdxs = nil
}
