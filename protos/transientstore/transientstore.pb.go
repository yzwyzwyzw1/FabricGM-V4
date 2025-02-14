// Code generated by protoc-gen-go. DO NOT EDIT.
// source: transientstore/transientstore.proto

package transientstore // import "github.com/chinaso/fabricGM/protos/transientstore"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import common "github.com/chinaso/fabricGM/protos/common"
import rwset "github.com/chinaso/fabricGM/protos/ledger/rwset"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// TxPvtReadWriteSetWithConfigInfo encapsulates the transaction's private
// read-write set and additional information about the configurations such as
// the latest collection config when the transaction is simulated
type TxPvtReadWriteSetWithConfigInfo struct {
	EndorsedAt           uint64                                     `protobuf:"varint,1,opt,name=endorsed_at,json=endorsedAt,proto3" json:"endorsed_at,omitempty"`
	PvtRwset             *rwset.TxPvtReadWriteSet                   `protobuf:"bytes,2,opt,name=pvt_rwset,json=pvtRwset,proto3" json:"pvt_rwset,omitempty"`
	CollectionConfigs    map[string]*common.CollectionConfigPackage `protobuf:"bytes,3,rep,name=collection_configs,json=collectionConfigs,proto3" json:"collection_configs,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}                                   `json:"-"`
	XXX_unrecognized     []byte                                     `json:"-"`
	XXX_sizecache        int32                                      `json:"-"`
}

func (m *TxPvtReadWriteSetWithConfigInfo) Reset()         { *m = TxPvtReadWriteSetWithConfigInfo{} }
func (m *TxPvtReadWriteSetWithConfigInfo) String() string { return proto.CompactTextString(m) }
func (*TxPvtReadWriteSetWithConfigInfo) ProtoMessage()    {}
func (*TxPvtReadWriteSetWithConfigInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_transientstore_7bb8c3b7e5ece488, []int{0}
}
func (m *TxPvtReadWriteSetWithConfigInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TxPvtReadWriteSetWithConfigInfo.Unmarshal(m, b)
}
func (m *TxPvtReadWriteSetWithConfigInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TxPvtReadWriteSetWithConfigInfo.Marshal(b, m, deterministic)
}
func (dst *TxPvtReadWriteSetWithConfigInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TxPvtReadWriteSetWithConfigInfo.Merge(dst, src)
}
func (m *TxPvtReadWriteSetWithConfigInfo) XXX_Size() int {
	return xxx_messageInfo_TxPvtReadWriteSetWithConfigInfo.Size(m)
}
func (m *TxPvtReadWriteSetWithConfigInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_TxPvtReadWriteSetWithConfigInfo.DiscardUnknown(m)
}

var xxx_messageInfo_TxPvtReadWriteSetWithConfigInfo proto.InternalMessageInfo

func (m *TxPvtReadWriteSetWithConfigInfo) GetEndorsedAt() uint64 {
	if m != nil {
		return m.EndorsedAt
	}
	return 0
}

func (m *TxPvtReadWriteSetWithConfigInfo) GetPvtRwset() *rwset.TxPvtReadWriteSet {
	if m != nil {
		return m.PvtRwset
	}
	return nil
}

func (m *TxPvtReadWriteSetWithConfigInfo) GetCollectionConfigs() map[string]*common.CollectionConfigPackage {
	if m != nil {
		return m.CollectionConfigs
	}
	return nil
}

func init() {
	proto.RegisterType((*TxPvtReadWriteSetWithConfigInfo)(nil), "transientstore.TxPvtReadWriteSetWithConfigInfo")
	proto.RegisterMapType((map[string]*common.CollectionConfigPackage)(nil), "transientstore.TxPvtReadWriteSetWithConfigInfo.CollectionConfigsEntry")
}

func init() {
	proto.RegisterFile("transientstore/transientstore.proto", fileDescriptor_transientstore_7bb8c3b7e5ece488)
}

var fileDescriptor_transientstore_7bb8c3b7e5ece488 = []byte{
	// 320 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x52, 0x4f, 0x4b, 0x3b, 0x31,
	0x10, 0x65, 0xdb, 0xdf, 0x4f, 0x6c, 0x0a, 0xa2, 0x39, 0xe8, 0xd2, 0x4b, 0x8b, 0x5e, 0x7a, 0x90,
	0x04, 0x5a, 0x0a, 0xe2, 0x4d, 0x8b, 0x82, 0xb7, 0x12, 0x85, 0x82, 0x97, 0x92, 0x66, 0xa7, 0xdb,
	0xd0, 0x6d, 0xb2, 0x24, 0xd3, 0xd5, 0x7e, 0x52, 0xbf, 0x8e, 0xec, 0xc6, 0x7f, 0xdd, 0x0a, 0x5e,
	0x96, 0xcd, 0x9b, 0xf7, 0xe6, 0xcd, 0x9b, 0x84, 0x5c, 0xa0, 0x93, 0xc6, 0x6b, 0x30, 0xe8, 0xd1,
	0x3a, 0xe0, 0xbb, 0x47, 0x96, 0x3b, 0x8b, 0x96, 0x1e, 0xed, 0xa2, 0x9d, 0x38, 0x83, 0x24, 0x05,
	0xc7, 0xdd, 0x8b, 0x07, 0x0c, 0xdf, 0xc0, 0xec, 0x9c, 0x29, 0xbb, 0x5e, 0x5b, 0xc3, 0x95, 0xcd,
	0x32, 0x50, 0xa8, 0xad, 0x09, 0x85, 0xf3, 0xb7, 0x06, 0xe9, 0x3e, 0xbd, 0x4e, 0x0a, 0x14, 0x20,
	0x93, 0xa9, 0xd3, 0x08, 0x8f, 0x80, 0x53, 0x8d, 0xcb, 0xb1, 0x35, 0x0b, 0x9d, 0x3e, 0x98, 0x85,
	0xa5, 0x5d, 0xd2, 0x06, 0x93, 0x58, 0xe7, 0x21, 0x99, 0x49, 0x8c, 0xa3, 0x5e, 0xd4, 0xff, 0x27,
	0xc8, 0x27, 0x74, 0x83, 0x74, 0x44, 0x5a, 0x79, 0x81, 0xb3, 0xca, 0x30, 0x6e, 0xf4, 0xa2, 0x7e,
	0x7b, 0x10, 0xb3, 0x60, 0xbf, 0xd7, 0x5b, 0x1c, 0xe6, 0x05, 0x8a, 0xb2, 0x46, 0x37, 0x84, 0x7e,
	0xcf, 0x33, 0x53, 0x95, 0xa1, 0x8f, 0x9b, 0xbd, 0x66, 0xbf, 0x3d, 0xb8, 0x67, 0xb5, 0xc4, 0x7f,
	0x0c, 0xc9, 0xc6, 0x5f, 0x9d, 0x02, 0xe8, 0xef, 0x0c, 0xba, 0xad, 0x38, 0x51, 0x75, 0xbc, 0x03,
	0xe4, 0xf4, 0x77, 0x32, 0x3d, 0x26, 0xcd, 0x15, 0x6c, 0xab, 0x80, 0x2d, 0x51, 0xfe, 0xd2, 0x11,
	0xf9, 0x5f, 0xc8, 0x6c, 0x03, 0x1f, 0xa9, 0xba, 0x2c, 0xec, 0x71, 0xcf, 0x6d, 0x22, 0xd5, 0x4a,
	0xa6, 0x20, 0x02, 0xfb, 0xba, 0x71, 0x15, 0xdd, 0x2a, 0x72, 0x69, 0x5d, 0xca, 0x96, 0xdb, 0x1c,
	0x5c, 0xb8, 0x17, 0xb6, 0x90, 0x73, 0xa7, 0x55, 0xd8, 0xbc, 0xaf, 0x05, 0x7c, 0x1e, 0xa6, 0x1a,
	0x97, 0x9b, 0x79, 0xe9, 0xc0, 0x7f, 0x88, 0x78, 0x10, 0xf1, 0x20, 0xaa, 0xbd, 0x83, 0xf9, 0x41,
	0x05, 0x0f, 0xdf, 0x03, 0x00, 0x00, 0xff, 0xff, 0x60, 0x8a, 0xb4, 0xba, 0x2f, 0x02, 0x00, 0x00,
}
