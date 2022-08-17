// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.15.8
// source: aggregator.proto

package aggregator

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

type Lwit struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DesignatedLogs []string `protobuf:"bytes,1,rep,name=DesignatedLogs,proto3" json:"DesignatedLogs,omitempty"`
	Log            string   `protobuf:"bytes,2,opt,name=Log,proto3" json:"Log,omitempty"`
	NdsHash        []byte   `protobuf:"bytes,3,opt,name=NdsHash,proto3" json:"NdsHash,omitempty"`
	Sig            []byte   `protobuf:"bytes,4,opt,name=Sig,proto3" json:"Sig,omitempty"`
	Data           []byte   `protobuf:"bytes,5,opt,name=Data,proto3" json:"Data,omitempty"`
}

func (x *Lwit) Reset() {
	*x = Lwit{}
	if protoimpl.UnsafeEnabled {
		mi := &file_aggregator_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Lwit) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Lwit) ProtoMessage() {}

func (x *Lwit) ProtoReflect() protoreflect.Message {
	mi := &file_aggregator_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Lwit.ProtoReflect.Descriptor instead.
func (*Lwit) Descriptor() ([]byte, []int) {
	return file_aggregator_proto_rawDescGZIP(), []int{0}
}

func (x *Lwit) GetDesignatedLogs() []string {
	if x != nil {
		return x.DesignatedLogs
	}
	return nil
}

func (x *Lwit) GetLog() string {
	if x != nil {
		return x.Log
	}
	return ""
}

func (x *Lwit) GetNdsHash() []byte {
	if x != nil {
		return x.NdsHash
	}
	return nil
}

func (x *Lwit) GetSig() []byte {
	if x != nil {
		return x.Sig
	}
	return nil
}

func (x *Lwit) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

type Acfm struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AggIdent string `protobuf:"bytes,1,opt,name=AggIdent,proto3" json:"AggIdent,omitempty"`
	NdsHash  []byte `protobuf:"bytes,2,opt,name=NdsHash,proto3" json:"NdsHash,omitempty"`
	DSum     []byte `protobuf:"bytes,3,opt,name=DSum,proto3" json:"DSum,omitempty"`
}

func (x *Acfm) Reset() {
	*x = Acfm{}
	if protoimpl.UnsafeEnabled {
		mi := &file_aggregator_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Acfm) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Acfm) ProtoMessage() {}

func (x *Acfm) ProtoReflect() protoreflect.Message {
	mi := &file_aggregator_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Acfm.ProtoReflect.Descriptor instead.
func (*Acfm) Descriptor() ([]byte, []int) {
	return file_aggregator_proto_rawDescGZIP(), []int{1}
}

func (x *Acfm) GetAggIdent() string {
	if x != nil {
		return x.AggIdent
	}
	return ""
}

func (x *Acfm) GetNdsHash() []byte {
	if x != nil {
		return x.NdsHash
	}
	return nil
}

func (x *Acfm) GetDSum() []byte {
	if x != nil {
		return x.DSum
	}
	return nil
}

type RetrieveDSALogRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestedZones []string `protobuf:"bytes,1,rep,name=RequestedZones,proto3" json:"RequestedZones,omitempty"`
}

func (x *RetrieveDSALogRequest) Reset() {
	*x = RetrieveDSALogRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_aggregator_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RetrieveDSALogRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RetrieveDSALogRequest) ProtoMessage() {}

func (x *RetrieveDSALogRequest) ProtoReflect() protoreflect.Message {
	mi := &file_aggregator_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RetrieveDSALogRequest.ProtoReflect.Descriptor instead.
func (*RetrieveDSALogRequest) Descriptor() ([]byte, []int) {
	return file_aggregator_proto_rawDescGZIP(), []int{2}
}

func (x *RetrieveDSALogRequest) GetRequestedZones() []string {
	if x != nil {
		return x.RequestedZones
	}
	return nil
}

type RetrieveDSALogResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DSAPayload    [][]byte `protobuf:"bytes,1,rep,name=DSAPayload,proto3" json:"DSAPayload,omitempty"`
	DSASignatures [][]byte `protobuf:"bytes,2,rep,name=DSASignatures,proto3" json:"DSASignatures,omitempty"`
}

func (x *RetrieveDSALogResponse) Reset() {
	*x = RetrieveDSALogResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_aggregator_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RetrieveDSALogResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RetrieveDSALogResponse) ProtoMessage() {}

func (x *RetrieveDSALogResponse) ProtoReflect() protoreflect.Message {
	mi := &file_aggregator_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RetrieveDSALogResponse.ProtoReflect.Descriptor instead.
func (*RetrieveDSALogResponse) Descriptor() ([]byte, []int) {
	return file_aggregator_proto_rawDescGZIP(), []int{3}
}

func (x *RetrieveDSALogResponse) GetDSAPayload() [][]byte {
	if x != nil {
		return x.DSAPayload
	}
	return nil
}

func (x *RetrieveDSALogResponse) GetDSASignatures() [][]byte {
	if x != nil {
		return x.DSASignatures
	}
	return nil
}

type SubmitNDSRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Nds           []byte  `protobuf:"bytes,1,opt,name=Nds,proto3" json:"Nds,omitempty"`
	Lwits         []*Lwit `protobuf:"bytes,2,rep,name=Lwits,proto3" json:"Lwits,omitempty"`
	Rid           []byte  `protobuf:"bytes,3,opt,name=Rid,proto3" json:"Rid,omitempty"`
	Rcertp        []byte  `protobuf:"bytes,4,opt,name=Rcertp,proto3" json:"Rcertp,omitempty"`
	Acsrpayload   []byte  `protobuf:"bytes,5,opt,name=Acsrpayload,proto3" json:"Acsrpayload,omitempty"`
	Acsrsignature []byte  `protobuf:"bytes,6,opt,name=Acsrsignature,proto3" json:"Acsrsignature,omitempty"`
}

func (x *SubmitNDSRequest) Reset() {
	*x = SubmitNDSRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_aggregator_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubmitNDSRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubmitNDSRequest) ProtoMessage() {}

func (x *SubmitNDSRequest) ProtoReflect() protoreflect.Message {
	mi := &file_aggregator_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubmitNDSRequest.ProtoReflect.Descriptor instead.
func (*SubmitNDSRequest) Descriptor() ([]byte, []int) {
	return file_aggregator_proto_rawDescGZIP(), []int{4}
}

func (x *SubmitNDSRequest) GetNds() []byte {
	if x != nil {
		return x.Nds
	}
	return nil
}

func (x *SubmitNDSRequest) GetLwits() []*Lwit {
	if x != nil {
		return x.Lwits
	}
	return nil
}

func (x *SubmitNDSRequest) GetRid() []byte {
	if x != nil {
		return x.Rid
	}
	return nil
}

func (x *SubmitNDSRequest) GetRcertp() []byte {
	if x != nil {
		return x.Rcertp
	}
	return nil
}

func (x *SubmitNDSRequest) GetAcsrpayload() []byte {
	if x != nil {
		return x.Acsrpayload
	}
	return nil
}

func (x *SubmitNDSRequest) GetAcsrsignature() []byte {
	if x != nil {
		return x.Acsrsignature
	}
	return nil
}

type SubmitNDSResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Acfmg []byte `protobuf:"bytes,1,opt,name=Acfmg,proto3" json:"Acfmg,omitempty"`
	Rid   []byte `protobuf:"bytes,2,opt,name=Rid,proto3" json:"Rid,omitempty"`
}

func (x *SubmitNDSResponse) Reset() {
	*x = SubmitNDSResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_aggregator_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubmitNDSResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubmitNDSResponse) ProtoMessage() {}

func (x *SubmitNDSResponse) ProtoReflect() protoreflect.Message {
	mi := &file_aggregator_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubmitNDSResponse.ProtoReflect.Descriptor instead.
func (*SubmitNDSResponse) Descriptor() ([]byte, []int) {
	return file_aggregator_proto_rawDescGZIP(), []int{5}
}

func (x *SubmitNDSResponse) GetAcfmg() []byte {
	if x != nil {
		return x.Acfmg
	}
	return nil
}

func (x *SubmitNDSResponse) GetRid() []byte {
	if x != nil {
		return x.Rid
	}
	return nil
}

var File_aggregator_proto protoreflect.FileDescriptor

var file_aggregator_proto_rawDesc = []byte{
	0x0a, 0x10, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x0a, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x6f, 0x72, 0x22, 0x80,
	0x01, 0x0a, 0x04, 0x4c, 0x77, 0x69, 0x74, 0x12, 0x26, 0x0a, 0x0e, 0x44, 0x65, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x65, 0x64, 0x4c, 0x6f, 0x67, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x0e, 0x44, 0x65, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x65, 0x64, 0x4c, 0x6f, 0x67, 0x73, 0x12,
	0x10, 0x0a, 0x03, 0x4c, 0x6f, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x4c, 0x6f,
	0x67, 0x12, 0x18, 0x0a, 0x07, 0x4e, 0x64, 0x73, 0x48, 0x61, 0x73, 0x68, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x4e, 0x64, 0x73, 0x48, 0x61, 0x73, 0x68, 0x12, 0x10, 0x0a, 0x03, 0x53,
	0x69, 0x67, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x53, 0x69, 0x67, 0x12, 0x12, 0x0a,
	0x04, 0x44, 0x61, 0x74, 0x61, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x44, 0x61, 0x74,
	0x61, 0x22, 0x50, 0x0a, 0x04, 0x41, 0x63, 0x66, 0x6d, 0x12, 0x1a, 0x0a, 0x08, 0x41, 0x67, 0x67,
	0x49, 0x64, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x41, 0x67, 0x67,
	0x49, 0x64, 0x65, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x4e, 0x64, 0x73, 0x48, 0x61, 0x73, 0x68,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x4e, 0x64, 0x73, 0x48, 0x61, 0x73, 0x68, 0x12,
	0x12, 0x0a, 0x04, 0x44, 0x53, 0x75, 0x6d, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x44,
	0x53, 0x75, 0x6d, 0x22, 0x3f, 0x0a, 0x15, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x44,
	0x53, 0x41, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x26, 0x0a, 0x0e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x65, 0x64, 0x5a, 0x6f, 0x6e, 0x65, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x0e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x65, 0x64, 0x5a,
	0x6f, 0x6e, 0x65, 0x73, 0x22, 0x5e, 0x0a, 0x16, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65,
	0x44, 0x53, 0x41, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1e,
	0x0a, 0x0a, 0x44, 0x53, 0x41, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x0a, 0x44, 0x53, 0x41, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x24,
	0x0a, 0x0d, 0x44, 0x53, 0x41, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x44, 0x53, 0x41, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x73, 0x22, 0xbe, 0x01, 0x0a, 0x10, 0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x4e,
	0x44, 0x53, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x4e, 0x64, 0x73,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x4e, 0x64, 0x73, 0x12, 0x26, 0x0a, 0x05, 0x4c,
	0x77, 0x69, 0x74, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x61, 0x67, 0x67,
	0x72, 0x65, 0x67, 0x61, 0x74, 0x6f, 0x72, 0x2e, 0x4c, 0x77, 0x69, 0x74, 0x52, 0x05, 0x4c, 0x77,
	0x69, 0x74, 0x73, 0x12, 0x10, 0x0a, 0x03, 0x52, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x03, 0x52, 0x69, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x52, 0x63, 0x65, 0x72, 0x74, 0x70, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x52, 0x63, 0x65, 0x72, 0x74, 0x70, 0x12, 0x20, 0x0a,
	0x0b, 0x41, 0x63, 0x73, 0x72, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x0b, 0x41, 0x63, 0x73, 0x72, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12,
	0x24, 0x0a, 0x0d, 0x41, 0x63, 0x73, 0x72, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d, 0x41, 0x63, 0x73, 0x72, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x3b, 0x0a, 0x11, 0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x4e,
	0x44, 0x53, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x41, 0x63,
	0x66, 0x6d, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x41, 0x63, 0x66, 0x6d, 0x67,
	0x12, 0x10, 0x0a, 0x03, 0x52, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x52,
	0x69, 0x64, 0x32, 0xb0, 0x01, 0x0a, 0x0a, 0x41, 0x67, 0x67, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x12, 0x56, 0x0a, 0x0b, 0x44, 0x53, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x61, 0x6c,
	0x12, 0x21, 0x2e, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x6f, 0x72, 0x2e, 0x52, 0x65,
	0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x44, 0x53, 0x41, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x22, 0x2e, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x6f, 0x72,
	0x2e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x44, 0x53, 0x41, 0x4c, 0x6f, 0x67, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x4a, 0x0a, 0x09, 0x53, 0x75, 0x62,
	0x6d, 0x69, 0x74, 0x4e, 0x44, 0x53, 0x12, 0x1c, 0x2e, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61,
	0x74, 0x6f, 0x72, 0x2e, 0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x4e, 0x44, 0x53, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x1d, 0x2e, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x6f,
	0x72, 0x2e, 0x53, 0x75, 0x62, 0x6d, 0x69, 0x74, 0x4e, 0x44, 0x53, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x49, 0x5a, 0x47, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x72, 0x68, 0x69, 0x6e, 0x65, 0x2d, 0x74, 0x65, 0x61, 0x6d, 0x2f, 0x52,
	0x48, 0x49, 0x4e, 0x45, 0x2d, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x6f,
	0x66, 0x66, 0x6c, 0x69, 0x6e, 0x65, 0x41, 0x75, 0x74, 0x68, 0x2f, 0x63, 0x6f, 0x6d, 0x70, 0x6f,
	0x6e, 0x65, 0x6e, 0x74, 0x73, 0x2f, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x6f, 0x72,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_aggregator_proto_rawDescOnce sync.Once
	file_aggregator_proto_rawDescData = file_aggregator_proto_rawDesc
)

func file_aggregator_proto_rawDescGZIP() []byte {
	file_aggregator_proto_rawDescOnce.Do(func() {
		file_aggregator_proto_rawDescData = protoimpl.X.CompressGZIP(file_aggregator_proto_rawDescData)
	})
	return file_aggregator_proto_rawDescData
}

var file_aggregator_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_aggregator_proto_goTypes = []interface{}{
	(*Lwit)(nil),                   // 0: aggregator.Lwit
	(*Acfm)(nil),                   // 1: aggregator.Acfm
	(*RetrieveDSALogRequest)(nil),  // 2: aggregator.RetrieveDSALogRequest
	(*RetrieveDSALogResponse)(nil), // 3: aggregator.RetrieveDSALogResponse
	(*SubmitNDSRequest)(nil),       // 4: aggregator.SubmitNDSRequest
	(*SubmitNDSResponse)(nil),      // 5: aggregator.SubmitNDSResponse
}
var file_aggregator_proto_depIdxs = []int32{
	0, // 0: aggregator.SubmitNDSRequest.Lwits:type_name -> aggregator.Lwit
	2, // 1: aggregator.AggService.DSRetrieval:input_type -> aggregator.RetrieveDSALogRequest
	4, // 2: aggregator.AggService.SubmitNDS:input_type -> aggregator.SubmitNDSRequest
	3, // 3: aggregator.AggService.DSRetrieval:output_type -> aggregator.RetrieveDSALogResponse
	5, // 4: aggregator.AggService.SubmitNDS:output_type -> aggregator.SubmitNDSResponse
	3, // [3:5] is the sub-list for method output_type
	1, // [1:3] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_aggregator_proto_init() }
func file_aggregator_proto_init() {
	if File_aggregator_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_aggregator_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Lwit); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_aggregator_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Acfm); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_aggregator_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RetrieveDSALogRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_aggregator_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RetrieveDSALogResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_aggregator_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubmitNDSRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_aggregator_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubmitNDSResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_aggregator_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_aggregator_proto_goTypes,
		DependencyIndexes: file_aggregator_proto_depIdxs,
		MessageInfos:      file_aggregator_proto_msgTypes,
	}.Build()
	File_aggregator_proto = out.File
	file_aggregator_proto_rawDesc = nil
	file_aggregator_proto_goTypes = nil
	file_aggregator_proto_depIdxs = nil
}
