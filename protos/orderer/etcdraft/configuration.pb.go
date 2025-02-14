// Code generated by protoc-gen-go. DO NOT EDIT.
// source: orderer/etcdraft/configuration.proto

package etcdraft // import "github.com/chinaso/fabricGM/protos/orderer/etcdraft"

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

// ConfigMetadata is serialized and set as the value of ConsensusType.Metadata in
// a channel configuration when the ConsensusType.Type is set "etcdraft".
type ConfigMetadata struct {
	Consenters           []*Consenter `protobuf:"bytes,1,rep,name=consenters,proto3" json:"consenters,omitempty"`
	Options              *Options     `protobuf:"bytes,2,opt,name=options,proto3" json:"options,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *ConfigMetadata) Reset()         { *m = ConfigMetadata{} }
func (m *ConfigMetadata) String() string { return proto.CompactTextString(m) }
func (*ConfigMetadata) ProtoMessage()    {}
func (*ConfigMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_780531726dd41db7, []int{0}
}
func (m *ConfigMetadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConfigMetadata.Unmarshal(m, b)
}
func (m *ConfigMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConfigMetadata.Marshal(b, m, deterministic)
}
func (dst *ConfigMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConfigMetadata.Merge(dst, src)
}
func (m *ConfigMetadata) XXX_Size() int {
	return xxx_messageInfo_ConfigMetadata.Size(m)
}
func (m *ConfigMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_ConfigMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_ConfigMetadata proto.InternalMessageInfo

func (m *ConfigMetadata) GetConsenters() []*Consenter {
	if m != nil {
		return m.Consenters
	}
	return nil
}

func (m *ConfigMetadata) GetOptions() *Options {
	if m != nil {
		return m.Options
	}
	return nil
}

// Consenter represents a consenting node (i.e. replica).
type Consenter struct {
	Host                 string   `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	Port                 uint32   `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	ClientTlsCert        []byte   `protobuf:"bytes,3,opt,name=client_tls_cert,json=clientTlsCert,proto3" json:"client_tls_cert,omitempty"`
	ServerTlsCert        []byte   `protobuf:"bytes,4,opt,name=server_tls_cert,json=serverTlsCert,proto3" json:"server_tls_cert,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Consenter) Reset()         { *m = Consenter{} }
func (m *Consenter) String() string { return proto.CompactTextString(m) }
func (*Consenter) ProtoMessage()    {}
func (*Consenter) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_780531726dd41db7, []int{1}
}
func (m *Consenter) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Consenter.Unmarshal(m, b)
}
func (m *Consenter) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Consenter.Marshal(b, m, deterministic)
}
func (dst *Consenter) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Consenter.Merge(dst, src)
}
func (m *Consenter) XXX_Size() int {
	return xxx_messageInfo_Consenter.Size(m)
}
func (m *Consenter) XXX_DiscardUnknown() {
	xxx_messageInfo_Consenter.DiscardUnknown(m)
}

var xxx_messageInfo_Consenter proto.InternalMessageInfo

func (m *Consenter) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

func (m *Consenter) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *Consenter) GetClientTlsCert() []byte {
	if m != nil {
		return m.ClientTlsCert
	}
	return nil
}

func (m *Consenter) GetServerTlsCert() []byte {
	if m != nil {
		return m.ServerTlsCert
	}
	return nil
}

// Options to be specified for all the etcd/raft nodes. These can be modified on a
// per-channel basis.
type Options struct {
	TickInterval      string `protobuf:"bytes,1,opt,name=tick_interval,json=tickInterval,proto3" json:"tick_interval,omitempty"`
	ElectionTick      uint32 `protobuf:"varint,2,opt,name=election_tick,json=electionTick,proto3" json:"election_tick,omitempty"`
	HeartbeatTick     uint32 `protobuf:"varint,3,opt,name=heartbeat_tick,json=heartbeatTick,proto3" json:"heartbeat_tick,omitempty"`
	MaxInflightBlocks uint32 `protobuf:"varint,4,opt,name=max_inflight_blocks,json=maxInflightBlocks,proto3" json:"max_inflight_blocks,omitempty"`
	// Take snapshot when cumulative data exceeds certain size in bytes.
	SnapshotIntervalSize uint32   `protobuf:"varint,5,opt,name=snapshot_interval_size,json=snapshotIntervalSize,proto3" json:"snapshot_interval_size,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Options) Reset()         { *m = Options{} }
func (m *Options) String() string { return proto.CompactTextString(m) }
func (*Options) ProtoMessage()    {}
func (*Options) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_780531726dd41db7, []int{2}
}
func (m *Options) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Options.Unmarshal(m, b)
}
func (m *Options) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Options.Marshal(b, m, deterministic)
}
func (dst *Options) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Options.Merge(dst, src)
}
func (m *Options) XXX_Size() int {
	return xxx_messageInfo_Options.Size(m)
}
func (m *Options) XXX_DiscardUnknown() {
	xxx_messageInfo_Options.DiscardUnknown(m)
}

var xxx_messageInfo_Options proto.InternalMessageInfo

func (m *Options) GetTickInterval() string {
	if m != nil {
		return m.TickInterval
	}
	return ""
}

func (m *Options) GetElectionTick() uint32 {
	if m != nil {
		return m.ElectionTick
	}
	return 0
}

func (m *Options) GetHeartbeatTick() uint32 {
	if m != nil {
		return m.HeartbeatTick
	}
	return 0
}

func (m *Options) GetMaxInflightBlocks() uint32 {
	if m != nil {
		return m.MaxInflightBlocks
	}
	return 0
}

func (m *Options) GetSnapshotIntervalSize() uint32 {
	if m != nil {
		return m.SnapshotIntervalSize
	}
	return 0
}

// BlockMetadata stores data used by the Raft OSNs when
// coordinating with each other, to be serialized into
// block meta dta field and used after failres and restarts.
type BlockMetadata struct {
	// Maintains a mapping between the cluster's OSNs
	// and their Raft IDs.
	ConsenterIds []uint64 `protobuf:"varint,1,rep,packed,name=consenter_ids,json=consenterIds,proto3" json:"consenter_ids,omitempty"`
	// Carries the Raft ID value that will be assigned
	// to the next OSN that will join this cluster.
	NextConsenterId uint64 `protobuf:"varint,2,opt,name=next_consenter_id,json=nextConsenterId,proto3" json:"next_consenter_id,omitempty"`
	// Index of etcd/raft entry for current block.
	RaftIndex            uint64   `protobuf:"varint,3,opt,name=raft_index,json=raftIndex,proto3" json:"raft_index,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BlockMetadata) Reset()         { *m = BlockMetadata{} }
func (m *BlockMetadata) String() string { return proto.CompactTextString(m) }
func (*BlockMetadata) ProtoMessage()    {}
func (*BlockMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_configuration_780531726dd41db7, []int{3}
}
func (m *BlockMetadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BlockMetadata.Unmarshal(m, b)
}
func (m *BlockMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BlockMetadata.Marshal(b, m, deterministic)
}
func (dst *BlockMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BlockMetadata.Merge(dst, src)
}
func (m *BlockMetadata) XXX_Size() int {
	return xxx_messageInfo_BlockMetadata.Size(m)
}
func (m *BlockMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_BlockMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_BlockMetadata proto.InternalMessageInfo

func (m *BlockMetadata) GetConsenterIds() []uint64 {
	if m != nil {
		return m.ConsenterIds
	}
	return nil
}

func (m *BlockMetadata) GetNextConsenterId() uint64 {
	if m != nil {
		return m.NextConsenterId
	}
	return 0
}

func (m *BlockMetadata) GetRaftIndex() uint64 {
	if m != nil {
		return m.RaftIndex
	}
	return 0
}

func init() {
	proto.RegisterType((*ConfigMetadata)(nil), "etcdraft.ConfigMetadata")
	proto.RegisterType((*Consenter)(nil), "etcdraft.Consenter")
	proto.RegisterType((*Options)(nil), "etcdraft.Options")
	proto.RegisterType((*BlockMetadata)(nil), "etcdraft.BlockMetadata")
}

func init() {
	proto.RegisterFile("orderer/etcdraft/configuration.proto", fileDescriptor_configuration_780531726dd41db7)
}

var fileDescriptor_configuration_780531726dd41db7 = []byte{
	// 448 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x92, 0xc1, 0x6f, 0xd3, 0x30,
	0x14, 0xc6, 0x15, 0x56, 0x18, 0x7d, 0x6b, 0x36, 0xd5, 0x43, 0x28, 0x17, 0xa4, 0xaa, 0x03, 0x54,
	0x81, 0x94, 0x48, 0x1b, 0xfc, 0x03, 0xeb, 0xa9, 0x07, 0x84, 0x14, 0x76, 0xe2, 0x62, 0x39, 0xce,
	0x6b, 0x62, 0x35, 0x8d, 0x23, 0xfb, 0x6d, 0x2a, 0xbb, 0x70, 0xe0, 0x1f, 0xe5, 0x4f, 0x41, 0xb6,
	0x93, 0xb4, 0xe2, 0x66, 0x7d, 0xdf, 0xef, 0xb3, 0x3f, 0xeb, 0x3d, 0x78, 0xaf, 0x4d, 0x89, 0x06,
	0x4d, 0x86, 0x24, 0x4b, 0x23, 0xb6, 0x94, 0x49, 0xdd, 0x6e, 0x55, 0xf5, 0x68, 0x04, 0x29, 0xdd,
	0xa6, 0x9d, 0xd1, 0xa4, 0xd9, 0xeb, 0xc1, 0x5d, 0x1a, 0xb8, 0x5c, 0x7b, 0xe0, 0x1b, 0x92, 0x28,
	0x05, 0x09, 0x76, 0x07, 0x20, 0x75, 0x6b, 0xb1, 0x25, 0x34, 0x36, 0x89, 0x16, 0x67, 0xab, 0x8b,
	0xdb, 0xeb, 0x74, 0x08, 0xa4, 0xeb, 0xc1, 0xcb, 0x4f, 0x30, 0xf6, 0x19, 0xce, 0x75, 0xe7, 0x1e,
	0xb0, 0xc9, 0x8b, 0x45, 0xb4, 0xba, 0xb8, 0x9d, 0x1f, 0x13, 0xdf, 0x83, 0x91, 0x0f, 0xc4, 0xf2,
	0x4f, 0x04, 0xd3, 0xf1, 0x1a, 0xc6, 0x60, 0x52, 0x6b, 0x4b, 0x49, 0xb4, 0x88, 0x56, 0xd3, 0xdc,
	0x9f, 0x9d, 0xd6, 0x69, 0x43, 0xfe, 0xae, 0x38, 0xf7, 0x67, 0xf6, 0x11, 0xae, 0x64, 0xa3, 0xb0,
	0x25, 0x4e, 0x8d, 0xe5, 0x12, 0x0d, 0x25, 0x67, 0x8b, 0x68, 0x35, 0xcb, 0xe3, 0x20, 0x3f, 0x34,
	0x76, 0x8d, 0x81, 0xb3, 0x68, 0x9e, 0xd0, 0x1c, 0xb9, 0x49, 0xe0, 0x82, 0xdc, 0x73, 0xcb, 0xbf,
	0x11, 0x9c, 0xf7, 0xd5, 0xd8, 0x0d, 0xc4, 0xa4, 0xe4, 0x8e, 0x2b, 0xd7, 0xe8, 0x49, 0x34, 0x7d,
	0x99, 0x99, 0x13, 0x37, 0xbd, 0xe6, 0x20, 0x6c, 0x50, 0xba, 0x04, 0x77, 0x46, 0xdf, 0x6e, 0x36,
	0x88, 0x0f, 0x4a, 0xee, 0xd8, 0x07, 0xb8, 0xac, 0x51, 0x18, 0x2a, 0x50, 0x50, 0xa0, 0xce, 0x3c,
	0x15, 0x8f, 0xaa, 0xc7, 0x52, 0xb8, 0xde, 0x8b, 0x03, 0x57, 0xed, 0xb6, 0x51, 0x55, 0x4d, 0xbc,
	0x68, 0xb4, 0xdc, 0x59, 0x5f, 0x34, 0xce, 0xe7, 0x7b, 0x71, 0xd8, 0xf4, 0xce, 0xbd, 0x37, 0xd8,
	0x17, 0x78, 0x6b, 0x5b, 0xd1, 0xd9, 0x5a, 0xd3, 0x58, 0x92, 0x5b, 0xf5, 0x8c, 0xc9, 0x4b, 0x1f,
	0x79, 0x33, 0xb8, 0x43, 0xdb, 0x1f, 0xea, 0x19, 0x97, 0xbf, 0x21, 0xf6, 0xf9, 0x71, 0xb6, 0x37,
	0x10, 0x8f, 0x43, 0xe3, 0xaa, 0x0c, 0xe3, 0x9d, 0xe4, 0xb3, 0x51, 0xdc, 0x94, 0x96, 0x7d, 0x82,
	0x79, 0x8b, 0x07, 0xe2, 0xa7, 0xa4, 0xff, 0xeb, 0x24, 0xbf, 0x72, 0xc6, 0xfa, 0x08, 0xb3, 0x77,
	0x00, 0x6e, 0xc6, 0x5c, 0xb5, 0x25, 0x1e, 0xfc, 0x57, 0x27, 0xf9, 0xd4, 0x29, 0x1b, 0x27, 0xdc,
	0x57, 0x90, 0x6a, 0x53, 0xa5, 0xf5, 0xaf, 0x0e, 0x4d, 0x83, 0x65, 0x85, 0x26, 0xdd, 0x8a, 0xc2,
	0x28, 0x19, 0xf6, 0xd0, 0xa6, 0xfd, 0xb6, 0x8e, 0xcb, 0xf2, 0xf3, 0x6b, 0xa5, 0xa8, 0x7e, 0x2c,
	0x52, 0xa9, 0xf7, 0xd9, 0x49, 0x2c, 0x0b, 0xb1, 0x2c, 0xc4, 0xb2, 0xff, 0x97, 0xbc, 0x78, 0xe5,
	0x8d, 0xbb, 0x7f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x7e, 0x1e, 0x2b, 0x0a, 0xff, 0x02, 0x00, 0x00,
}
