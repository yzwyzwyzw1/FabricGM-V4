// Code generated by protoc-gen-go. DO NOT EDIT.
// source: orderer/cluster.proto

package orderer // import "github.com/chinaso/fabricGM/protos/orderer"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import common "github.com/chinaso/fabricGM/protos/common"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// StepRequest wraps a message that is sent to a cluster member.
type StepRequest struct {
	// Types that are valid to be assigned to Payload:
	//	*StepRequest_ConsensusRequest
	//	*StepRequest_SubmitRequest
	Payload              isStepRequest_Payload `protobuf_oneof:"payload"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *StepRequest) Reset()         { *m = StepRequest{} }
func (m *StepRequest) String() string { return proto.CompactTextString(m) }
func (*StepRequest) ProtoMessage()    {}
func (*StepRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cluster_d9833ceca5c79414, []int{0}
}
func (m *StepRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StepRequest.Unmarshal(m, b)
}
func (m *StepRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StepRequest.Marshal(b, m, deterministic)
}
func (dst *StepRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StepRequest.Merge(dst, src)
}
func (m *StepRequest) XXX_Size() int {
	return xxx_messageInfo_StepRequest.Size(m)
}
func (m *StepRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_StepRequest.DiscardUnknown(m)
}

var xxx_messageInfo_StepRequest proto.InternalMessageInfo

type isStepRequest_Payload interface {
	isStepRequest_Payload()
}

type StepRequest_ConsensusRequest struct {
	ConsensusRequest *ConsensusRequest `protobuf:"bytes,1,opt,name=consensus_request,json=consensusRequest,proto3,oneof"`
}

type StepRequest_SubmitRequest struct {
	SubmitRequest *SubmitRequest `protobuf:"bytes,2,opt,name=submit_request,json=submitRequest,proto3,oneof"`
}

func (*StepRequest_ConsensusRequest) isStepRequest_Payload() {}

func (*StepRequest_SubmitRequest) isStepRequest_Payload() {}

func (m *StepRequest) GetPayload() isStepRequest_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *StepRequest) GetConsensusRequest() *ConsensusRequest {
	if x, ok := m.GetPayload().(*StepRequest_ConsensusRequest); ok {
		return x.ConsensusRequest
	}
	return nil
}

func (m *StepRequest) GetSubmitRequest() *SubmitRequest {
	if x, ok := m.GetPayload().(*StepRequest_SubmitRequest); ok {
		return x.SubmitRequest
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*StepRequest) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _StepRequest_OneofMarshaler, _StepRequest_OneofUnmarshaler, _StepRequest_OneofSizer, []interface{}{
		(*StepRequest_ConsensusRequest)(nil),
		(*StepRequest_SubmitRequest)(nil),
	}
}

func _StepRequest_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*StepRequest)
	// payload
	switch x := m.Payload.(type) {
	case *StepRequest_ConsensusRequest:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.ConsensusRequest); err != nil {
			return err
		}
	case *StepRequest_SubmitRequest:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.SubmitRequest); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("StepRequest.Payload has unexpected type %T", x)
	}
	return nil
}

func _StepRequest_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*StepRequest)
	switch tag {
	case 1: // payload.consensus_request
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(ConsensusRequest)
		err := b.DecodeMessage(msg)
		m.Payload = &StepRequest_ConsensusRequest{msg}
		return true, err
	case 2: // payload.submit_request
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(SubmitRequest)
		err := b.DecodeMessage(msg)
		m.Payload = &StepRequest_SubmitRequest{msg}
		return true, err
	default:
		return false, nil
	}
}

func _StepRequest_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*StepRequest)
	// payload
	switch x := m.Payload.(type) {
	case *StepRequest_ConsensusRequest:
		s := proto.Size(x.ConsensusRequest)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *StepRequest_SubmitRequest:
		s := proto.Size(x.SubmitRequest)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// StepResponse is a message received from a cluster member.
type StepResponse struct {
	// Types that are valid to be assigned to Payload:
	//	*StepResponse_SubmitRes
	Payload              isStepResponse_Payload `protobuf_oneof:"payload"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *StepResponse) Reset()         { *m = StepResponse{} }
func (m *StepResponse) String() string { return proto.CompactTextString(m) }
func (*StepResponse) ProtoMessage()    {}
func (*StepResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_cluster_d9833ceca5c79414, []int{1}
}
func (m *StepResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StepResponse.Unmarshal(m, b)
}
func (m *StepResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StepResponse.Marshal(b, m, deterministic)
}
func (dst *StepResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StepResponse.Merge(dst, src)
}
func (m *StepResponse) XXX_Size() int {
	return xxx_messageInfo_StepResponse.Size(m)
}
func (m *StepResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_StepResponse.DiscardUnknown(m)
}

var xxx_messageInfo_StepResponse proto.InternalMessageInfo

type isStepResponse_Payload interface {
	isStepResponse_Payload()
}

type StepResponse_SubmitRes struct {
	SubmitRes *SubmitResponse `protobuf:"bytes,1,opt,name=submit_res,json=submitRes,proto3,oneof"`
}

func (*StepResponse_SubmitRes) isStepResponse_Payload() {}

func (m *StepResponse) GetPayload() isStepResponse_Payload {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *StepResponse) GetSubmitRes() *SubmitResponse {
	if x, ok := m.GetPayload().(*StepResponse_SubmitRes); ok {
		return x.SubmitRes
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*StepResponse) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _StepResponse_OneofMarshaler, _StepResponse_OneofUnmarshaler, _StepResponse_OneofSizer, []interface{}{
		(*StepResponse_SubmitRes)(nil),
	}
}

func _StepResponse_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*StepResponse)
	// payload
	switch x := m.Payload.(type) {
	case *StepResponse_SubmitRes:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.SubmitRes); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("StepResponse.Payload has unexpected type %T", x)
	}
	return nil
}

func _StepResponse_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*StepResponse)
	switch tag {
	case 1: // payload.submit_res
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(SubmitResponse)
		err := b.DecodeMessage(msg)
		m.Payload = &StepResponse_SubmitRes{msg}
		return true, err
	default:
		return false, nil
	}
}

func _StepResponse_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*StepResponse)
	// payload
	switch x := m.Payload.(type) {
	case *StepResponse_SubmitRes:
		s := proto.Size(x.SubmitRes)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// ConsensusRequest is a consensus specific message sent to a cluster member.
type ConsensusRequest struct {
	Channel              string   `protobuf:"bytes,1,opt,name=channel,proto3" json:"channel,omitempty"`
	Payload              []byte   `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ConsensusRequest) Reset()         { *m = ConsensusRequest{} }
func (m *ConsensusRequest) String() string { return proto.CompactTextString(m) }
func (*ConsensusRequest) ProtoMessage()    {}
func (*ConsensusRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cluster_d9833ceca5c79414, []int{2}
}
func (m *ConsensusRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConsensusRequest.Unmarshal(m, b)
}
func (m *ConsensusRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConsensusRequest.Marshal(b, m, deterministic)
}
func (dst *ConsensusRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConsensusRequest.Merge(dst, src)
}
func (m *ConsensusRequest) XXX_Size() int {
	return xxx_messageInfo_ConsensusRequest.Size(m)
}
func (m *ConsensusRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ConsensusRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ConsensusRequest proto.InternalMessageInfo

func (m *ConsensusRequest) GetChannel() string {
	if m != nil {
		return m.Channel
	}
	return ""
}

func (m *ConsensusRequest) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

// SubmitRequest wraps a transaction to be sent for ordering.
type SubmitRequest struct {
	Channel string `protobuf:"bytes,1,opt,name=channel,proto3" json:"channel,omitempty"`
	// last_validation_seq denotes the last
	// configuration sequence at which the
	// sender validated this message.
	LastValidationSeq uint64 `protobuf:"varint,2,opt,name=last_validation_seq,json=lastValidationSeq,proto3" json:"last_validation_seq,omitempty"`
	// content is the fabric transaction
	// that is forwarded to the cluster member.
	Payload              *common.Envelope `protobuf:"bytes,3,opt,name=payload,proto3" json:"payload,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *SubmitRequest) Reset()         { *m = SubmitRequest{} }
func (m *SubmitRequest) String() string { return proto.CompactTextString(m) }
func (*SubmitRequest) ProtoMessage()    {}
func (*SubmitRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_cluster_d9833ceca5c79414, []int{3}
}
func (m *SubmitRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SubmitRequest.Unmarshal(m, b)
}
func (m *SubmitRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SubmitRequest.Marshal(b, m, deterministic)
}
func (dst *SubmitRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SubmitRequest.Merge(dst, src)
}
func (m *SubmitRequest) XXX_Size() int {
	return xxx_messageInfo_SubmitRequest.Size(m)
}
func (m *SubmitRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_SubmitRequest.DiscardUnknown(m)
}

var xxx_messageInfo_SubmitRequest proto.InternalMessageInfo

func (m *SubmitRequest) GetChannel() string {
	if m != nil {
		return m.Channel
	}
	return ""
}

func (m *SubmitRequest) GetLastValidationSeq() uint64 {
	if m != nil {
		return m.LastValidationSeq
	}
	return 0
}

func (m *SubmitRequest) GetPayload() *common.Envelope {
	if m != nil {
		return m.Payload
	}
	return nil
}

// SubmitResponse returns a success
// or failure status to the sender.
type SubmitResponse struct {
	Channel string `protobuf:"bytes,1,opt,name=channel,proto3" json:"channel,omitempty"`
	// Status code, which may be used to programatically respond to success/failure.
	Status common.Status `protobuf:"varint,2,opt,name=status,proto3,enum=common.Status" json:"status,omitempty"`
	// Info string which may contain additional information about the returned status.
	Info                 string   `protobuf:"bytes,3,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SubmitResponse) Reset()         { *m = SubmitResponse{} }
func (m *SubmitResponse) String() string { return proto.CompactTextString(m) }
func (*SubmitResponse) ProtoMessage()    {}
func (*SubmitResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_cluster_d9833ceca5c79414, []int{4}
}
func (m *SubmitResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SubmitResponse.Unmarshal(m, b)
}
func (m *SubmitResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SubmitResponse.Marshal(b, m, deterministic)
}
func (dst *SubmitResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SubmitResponse.Merge(dst, src)
}
func (m *SubmitResponse) XXX_Size() int {
	return xxx_messageInfo_SubmitResponse.Size(m)
}
func (m *SubmitResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SubmitResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SubmitResponse proto.InternalMessageInfo

func (m *SubmitResponse) GetChannel() string {
	if m != nil {
		return m.Channel
	}
	return ""
}

func (m *SubmitResponse) GetStatus() common.Status {
	if m != nil {
		return m.Status
	}
	return common.Status_UNKNOWN
}

func (m *SubmitResponse) GetInfo() string {
	if m != nil {
		return m.Info
	}
	return ""
}

func init() {
	proto.RegisterType((*StepRequest)(nil), "orderer.StepRequest")
	proto.RegisterType((*StepResponse)(nil), "orderer.StepResponse")
	proto.RegisterType((*ConsensusRequest)(nil), "orderer.ConsensusRequest")
	proto.RegisterType((*SubmitRequest)(nil), "orderer.SubmitRequest")
	proto.RegisterType((*SubmitResponse)(nil), "orderer.SubmitResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// ClusterClient is the client API for Cluster service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ClusterClient interface {
	// Step passes an implementation-specific message to another cluster member.
	Step(ctx context.Context, opts ...grpc.CallOption) (Cluster_StepClient, error)
}

type clusterClient struct {
	cc *grpc.ClientConn
}

func NewClusterClient(cc *grpc.ClientConn) ClusterClient {
	return &clusterClient{cc}
}

func (c *clusterClient) Step(ctx context.Context, opts ...grpc.CallOption) (Cluster_StepClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Cluster_serviceDesc.Streams[0], "/orderer.Cluster/Step", opts...)
	if err != nil {
		return nil, err
	}
	x := &clusterStepClient{stream}
	return x, nil
}

type Cluster_StepClient interface {
	Send(*StepRequest) error
	Recv() (*StepResponse, error)
	grpc.ClientStream
}

type clusterStepClient struct {
	grpc.ClientStream
}

func (x *clusterStepClient) Send(m *StepRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *clusterStepClient) Recv() (*StepResponse, error) {
	m := new(StepResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ClusterServer is the server API for Cluster service.
type ClusterServer interface {
	// Step passes an implementation-specific message to another cluster member.
	Step(Cluster_StepServer) error
}

func RegisterClusterServer(s *grpc.Server, srv ClusterServer) {
	s.RegisterService(&_Cluster_serviceDesc, srv)
}

func _Cluster_Step_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ClusterServer).Step(&clusterStepServer{stream})
}

type Cluster_StepServer interface {
	Send(*StepResponse) error
	Recv() (*StepRequest, error)
	grpc.ServerStream
}

type clusterStepServer struct {
	grpc.ServerStream
}

func (x *clusterStepServer) Send(m *StepResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *clusterStepServer) Recv() (*StepRequest, error) {
	m := new(StepRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _Cluster_serviceDesc = grpc.ServiceDesc{
	ServiceName: "orderer.Cluster",
	HandlerType: (*ClusterServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Step",
			Handler:       _Cluster_Step_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "orderer/cluster.proto",
}

func init() { proto.RegisterFile("orderer/cluster.proto", fileDescriptor_cluster_d9833ceca5c79414) }

var fileDescriptor_cluster_d9833ceca5c79414 = []byte{
	// 399 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0xd1, 0xee, 0xd2, 0x30,
	0x14, 0xc6, 0xff, 0x53, 0xc2, 0xb2, 0x03, 0x2c, 0x50, 0x44, 0x91, 0x2b, 0x43, 0xa2, 0x21, 0xc6,
	0x6c, 0x06, 0x2f, 0xf4, 0xce, 0x04, 0xa2, 0xe1, 0xba, 0x8b, 0x5e, 0x78, 0x43, 0xba, 0xad, 0xc0,
	0x92, 0xd1, 0x8e, 0xb6, 0x23, 0xe1, 0x01, 0x7c, 0x12, 0x5f, 0xd4, 0xac, 0xed, 0x36, 0xe0, 0x9f,
	0x70, 0x05, 0x3d, 0xdf, 0xd7, 0xdf, 0xf9, 0xce, 0x7a, 0x60, 0xc2, 0x45, 0x4a, 0x05, 0x15, 0x61,
	0x92, 0x97, 0x52, 0x51, 0x11, 0x14, 0x82, 0x2b, 0x8e, 0x5c, 0x5b, 0x9e, 0x8d, 0x13, 0x7e, 0x3c,
	0x72, 0x16, 0x9a, 0x1f, 0xa3, 0xce, 0xff, 0x39, 0xd0, 0x8b, 0x14, 0x2d, 0x30, 0x3d, 0x95, 0x54,
	0x2a, 0xb4, 0x81, 0x51, 0xc2, 0x99, 0xa4, 0x4c, 0x96, 0x72, 0x2b, 0x4c, 0x71, 0xea, 0xbc, 0x73,
	0x16, 0xbd, 0xe5, 0xdb, 0xc0, 0x92, 0x82, 0x75, 0xed, 0xb0, 0xb7, 0x36, 0x4f, 0x78, 0x98, 0xdc,
	0xd5, 0xd0, 0x77, 0xf0, 0x65, 0x19, 0x1f, 0x33, 0xd5, 0x60, 0x5e, 0x68, 0xcc, 0xeb, 0x06, 0x13,
	0x69, 0xb9, 0x65, 0x0c, 0xe4, 0x75, 0x61, 0xe5, 0x81, 0x5b, 0x90, 0x4b, 0xce, 0x49, 0x3a, 0x8f,
	0xa0, 0x6f, 0x42, 0xca, 0xa2, 0x6a, 0x83, 0xbe, 0x01, 0x34, 0x6c, 0x69, 0xe3, 0xbd, 0x79, 0xc6,
	0x35, 0xe6, 0xcd, 0x13, 0xf6, 0x6a, 0xb0, 0xbc, 0x86, 0xfe, 0x84, 0xe1, 0xfd, 0x20, 0x68, 0x0a,
	0x6e, 0x72, 0x20, 0x8c, 0xd1, 0x5c, 0x53, 0x3d, 0x5c, 0x1f, 0x2b, 0xc5, 0x5e, 0xd4, 0x73, 0xf4,
	0x71, 0xc3, 0xf9, 0xeb, 0xc0, 0xe0, 0x66, 0x94, 0x07, 0x94, 0x00, 0xc6, 0x39, 0x91, 0x6a, 0x7b,
	0x26, 0x79, 0x96, 0x12, 0x95, 0x71, 0xb6, 0x95, 0xf4, 0xa4, 0x89, 0x1d, 0x3c, 0xaa, 0xa4, 0xdf,
	0x8d, 0x12, 0xd1, 0x13, 0xfa, 0xd8, 0x76, 0x7d, 0xa9, 0xa7, 0x1c, 0x06, 0xf6, 0xf9, 0x7e, 0xb0,
	0x33, 0xcd, 0x79, 0x41, 0xdb, 0x1c, 0x3b, 0xf0, 0x6f, 0x27, 0x7f, 0x90, 0xe3, 0x03, 0x74, 0xa5,
	0x22, 0xaa, 0x94, 0xba, 0xb5, 0xbf, 0xf4, 0x6b, 0x6c, 0xa4, 0xab, 0xd8, 0xaa, 0x08, 0x41, 0x27,
	0x63, 0x3b, 0xae, 0x9b, 0x7b, 0x58, 0xff, 0x5f, 0xae, 0xc0, 0x5d, 0x9b, 0x0d, 0x43, 0x5f, 0xa1,
	0x53, 0xbd, 0x0b, 0x7a, 0xd5, 0x7e, 0xfb, 0x76, 0x97, 0x66, 0x93, 0xbb, 0xaa, 0x49, 0xb5, 0x70,
	0x3e, 0x3b, 0xab, 0x5f, 0xf0, 0x9e, 0x8b, 0x7d, 0x70, 0xb8, 0x14, 0x54, 0xe4, 0x34, 0xdd, 0x53,
	0x11, 0xec, 0x48, 0x2c, 0xb2, 0xc4, 0xac, 0xa5, 0xac, 0x6f, 0xfe, 0xf9, 0xb4, 0xcf, 0xd4, 0xa1,
	0x8c, 0xab, 0x78, 0xe1, 0x95, 0x3b, 0x34, 0xee, 0xd0, 0xb8, 0x43, 0xeb, 0x8e, 0xbb, 0xfa, 0xfc,
	0xe5, 0x7f, 0x00, 0x00, 0x00, 0xff, 0xff, 0xcc, 0xe7, 0xa4, 0xe2, 0x0b, 0x03, 0x00, 0x00,
}
