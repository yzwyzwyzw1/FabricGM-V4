// Code generated by protoc-gen-go. DO NOT EDIT.
// source: pvtdata_key.proto

package pvtstatepurgemgmt // import "github.com/chinaso/fabricGM/core/ledger/kvledger/txmgmt/pvtstatepurgemgmt"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type PvtdataKeys struct {
	Map                  map[string]*Collections `protobuf:"bytes,1,rep,name=map,proto3" json:"map,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}                `json:"-"`
	XXX_unrecognized     []byte                  `json:"-"`
	XXX_sizecache        int32                   `json:"-"`
}

func (m *PvtdataKeys) Reset()         { *m = PvtdataKeys{} }
func (m *PvtdataKeys) String() string { return proto.CompactTextString(m) }
func (*PvtdataKeys) ProtoMessage()    {}
func (*PvtdataKeys) Descriptor() ([]byte, []int) {
	return fileDescriptor_pvtdata_key_a4c461a959db81b6, []int{0}
}
func (m *PvtdataKeys) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PvtdataKeys.Unmarshal(m, b)
}
func (m *PvtdataKeys) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PvtdataKeys.Marshal(b, m, deterministic)
}
func (dst *PvtdataKeys) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PvtdataKeys.Merge(dst, src)
}
func (m *PvtdataKeys) XXX_Size() int {
	return xxx_messageInfo_PvtdataKeys.Size(m)
}
func (m *PvtdataKeys) XXX_DiscardUnknown() {
	xxx_messageInfo_PvtdataKeys.DiscardUnknown(m)
}

var xxx_messageInfo_PvtdataKeys proto.InternalMessageInfo

func (m *PvtdataKeys) GetMap() map[string]*Collections {
	if m != nil {
		return m.Map
	}
	return nil
}

type Collections struct {
	Map                  map[string]*KeysAndHashes `protobuf:"bytes,1,rep,name=map,proto3" json:"map,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}                  `json:"-"`
	XXX_unrecognized     []byte                    `json:"-"`
	XXX_sizecache        int32                     `json:"-"`
}

func (m *Collections) Reset()         { *m = Collections{} }
func (m *Collections) String() string { return proto.CompactTextString(m) }
func (*Collections) ProtoMessage()    {}
func (*Collections) Descriptor() ([]byte, []int) {
	return fileDescriptor_pvtdata_key_a4c461a959db81b6, []int{1}
}
func (m *Collections) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Collections.Unmarshal(m, b)
}
func (m *Collections) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Collections.Marshal(b, m, deterministic)
}
func (dst *Collections) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Collections.Merge(dst, src)
}
func (m *Collections) XXX_Size() int {
	return xxx_messageInfo_Collections.Size(m)
}
func (m *Collections) XXX_DiscardUnknown() {
	xxx_messageInfo_Collections.DiscardUnknown(m)
}

var xxx_messageInfo_Collections proto.InternalMessageInfo

func (m *Collections) GetMap() map[string]*KeysAndHashes {
	if m != nil {
		return m.Map
	}
	return nil
}

type KeysAndHashes struct {
	List                 []*KeyAndHash `protobuf:"bytes,1,rep,name=list,proto3" json:"list,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *KeysAndHashes) Reset()         { *m = KeysAndHashes{} }
func (m *KeysAndHashes) String() string { return proto.CompactTextString(m) }
func (*KeysAndHashes) ProtoMessage()    {}
func (*KeysAndHashes) Descriptor() ([]byte, []int) {
	return fileDescriptor_pvtdata_key_a4c461a959db81b6, []int{2}
}
func (m *KeysAndHashes) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeysAndHashes.Unmarshal(m, b)
}
func (m *KeysAndHashes) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeysAndHashes.Marshal(b, m, deterministic)
}
func (dst *KeysAndHashes) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeysAndHashes.Merge(dst, src)
}
func (m *KeysAndHashes) XXX_Size() int {
	return xxx_messageInfo_KeysAndHashes.Size(m)
}
func (m *KeysAndHashes) XXX_DiscardUnknown() {
	xxx_messageInfo_KeysAndHashes.DiscardUnknown(m)
}

var xxx_messageInfo_KeysAndHashes proto.InternalMessageInfo

func (m *KeysAndHashes) GetList() []*KeyAndHash {
	if m != nil {
		return m.List
	}
	return nil
}

type KeyAndHash struct {
	Key                  string   `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Hash                 []byte   `protobuf:"bytes,2,opt,name=hash,proto3" json:"hash,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *KeyAndHash) Reset()         { *m = KeyAndHash{} }
func (m *KeyAndHash) String() string { return proto.CompactTextString(m) }
func (*KeyAndHash) ProtoMessage()    {}
func (*KeyAndHash) Descriptor() ([]byte, []int) {
	return fileDescriptor_pvtdata_key_a4c461a959db81b6, []int{3}
}
func (m *KeyAndHash) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyAndHash.Unmarshal(m, b)
}
func (m *KeyAndHash) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyAndHash.Marshal(b, m, deterministic)
}
func (dst *KeyAndHash) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyAndHash.Merge(dst, src)
}
func (m *KeyAndHash) XXX_Size() int {
	return xxx_messageInfo_KeyAndHash.Size(m)
}
func (m *KeyAndHash) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyAndHash.DiscardUnknown(m)
}

var xxx_messageInfo_KeyAndHash proto.InternalMessageInfo

func (m *KeyAndHash) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *KeyAndHash) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func init() {
	proto.RegisterType((*PvtdataKeys)(nil), "pvtstatepurgemgmt.PvtdataKeys")
	proto.RegisterMapType((map[string]*Collections)(nil), "pvtstatepurgemgmt.PvtdataKeys.MapEntry")
	proto.RegisterType((*Collections)(nil), "pvtstatepurgemgmt.Collections")
	proto.RegisterMapType((map[string]*KeysAndHashes)(nil), "pvtstatepurgemgmt.Collections.MapEntry")
	proto.RegisterType((*KeysAndHashes)(nil), "pvtstatepurgemgmt.KeysAndHashes")
	proto.RegisterType((*KeyAndHash)(nil), "pvtstatepurgemgmt.KeyAndHash")
}

func init() { proto.RegisterFile("pvtdata_key.proto", fileDescriptor_pvtdata_key_a4c461a959db81b6) }

var fileDescriptor_pvtdata_key_a4c461a959db81b6 = []byte{
	// 297 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0x4d, 0x4b, 0xc3, 0x40,
	0x10, 0x86, 0xd9, 0xb6, 0x8a, 0x4e, 0x14, 0x74, 0x4f, 0x45, 0x50, 0x42, 0x2f, 0xf6, 0x94, 0x60,
	0x14, 0x51, 0x6f, 0x56, 0x04, 0xa1, 0x14, 0x24, 0x07, 0x11, 0x2f, 0xb2, 0x49, 0xc6, 0x24, 0xe4,
	0x63, 0x97, 0xdd, 0x4d, 0x30, 0xff, 0x46, 0xfc, 0xa5, 0x92, 0x34, 0x62, 0x62, 0x83, 0xde, 0x86,
	0x77, 0x9e, 0x79, 0x79, 0x16, 0x16, 0x0e, 0x45, 0xa9, 0x03, 0xa6, 0xd9, 0x6b, 0x82, 0x95, 0x25,
	0x24, 0xd7, 0x9c, 0xd6, 0x91, 0xd2, 0x4c, 0xa3, 0x28, 0x64, 0x88, 0x59, 0x98, 0xe9, 0xd9, 0x07,
	0x01, 0xe3, 0x71, 0x0d, 0x2e, 0xb1, 0x52, 0xf4, 0x1a, 0xc6, 0x19, 0x13, 0x53, 0x62, 0x8e, 0xe7,
	0x86, 0x73, 0x6a, 0x6d, 0x1c, 0x58, 0x1d, 0xd8, 0x5a, 0x31, 0x71, 0x9f, 0x6b, 0x59, 0xb9, 0xf5,
	0xcd, 0xd1, 0x13, 0xec, 0x7c, 0x07, 0xf4, 0x00, 0xc6, 0x09, 0x56, 0x53, 0x62, 0x92, 0xf9, 0xae,
	0x5b, 0x8f, 0xf4, 0x02, 0xb6, 0x4a, 0x96, 0x16, 0x38, 0x1d, 0x99, 0x64, 0x6e, 0x38, 0x27, 0x03,
	0xd5, 0x77, 0x3c, 0x4d, 0xd1, 0xd7, 0x31, 0xcf, 0x95, 0xbb, 0x86, 0x6f, 0x46, 0x57, 0x64, 0xf6,
	0x49, 0xc0, 0xe8, 0xac, 0xfe, 0x57, 0xec, 0xc0, 0xbf, 0x14, 0x9f, 0xff, 0x54, 0xbc, 0xec, 0x2b,
	0x9a, 0x03, 0xd5, 0xf5, 0xb3, 0x6f, 0xf3, 0xe0, 0x81, 0xa9, 0x08, 0x7b, 0x92, 0x0b, 0xd8, 0xef,
	0xed, 0xe8, 0x19, 0x4c, 0xd2, 0x58, 0xe9, 0x56, 0xf3, 0x78, 0xb8, 0xab, 0xc5, 0xdd, 0x06, 0x9d,
	0x39, 0x00, 0x3f, 0xd9, 0x80, 0x1f, 0x85, 0x49, 0xc4, 0x54, 0xd4, 0xe8, 0xed, 0xb9, 0xcd, 0xbc,
	0x58, 0xbd, 0x2c, 0xc3, 0x58, 0x47, 0x85, 0x67, 0xf9, 0x3c, 0xb3, 0xa3, 0x4a, 0xa0, 0x4c, 0x31,
	0x08, 0x51, 0xda, 0x6f, 0xcc, 0x93, 0xb1, 0x6f, 0xfb, 0x5c, 0xa2, 0xdd, 0x46, 0x49, 0xd9, 0x0e,
	0xfa, 0xbd, 0x36, 0xb0, 0x37, 0x9c, 0xbc, 0xed, 0xe6, 0xa3, 0x9c, 0x7f, 0x05, 0x00, 0x00, 0xff,
	0xff, 0xdf, 0x2c, 0x02, 0xd0, 0x3d, 0x02, 0x00, 0x00,
}
