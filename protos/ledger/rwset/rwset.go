/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package rwset

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/chinaso/fabricGM/protos/ledger/rwset/kvrwset"
)

func (txrws *TxReadWriteSet) DynamicSliceFields() []string {
	if txrws.DataModel != TxReadWriteSet_KV {
		// We only know how to handle TxReadWriteSet_KV types
		return []string{}
	}

	return []string{"ns_rwset"}
}

func (txrws *TxReadWriteSet) DynamicSliceFieldProto(name string, index int, base proto.Message) (proto.Message, error) {
	if name != txrws.DynamicSliceFields()[0] {
		return nil, fmt.Errorf("Not a dynamic field: %s", name)
	}

	nsrw, ok := base.(*NsReadWriteSet)
	if !ok {
		return nil, fmt.Errorf("TxReadWriteSet must embed a NsReadWriteSet its dynamic field")
	}

	return &DynamicNsReadWriteSet{
		NsReadWriteSet: nsrw,
		DataModel:      txrws.DataModel,
	}, nil
}

type DynamicNsReadWriteSet struct {
	*NsReadWriteSet
	DataModel TxReadWriteSet_DataModel
}

func (dnrws *DynamicNsReadWriteSet) Underlying() proto.Message {
	return dnrws.NsReadWriteSet
}

func (dnrws *DynamicNsReadWriteSet) StaticallyOpaqueFields() []string {
	return []string{"rwset"}
}

func (dnrws *DynamicNsReadWriteSet) StaticallyOpaqueFieldProto(name string) (proto.Message, error) {
	switch name {
	case "rwset":
		switch dnrws.DataModel {
		case TxReadWriteSet_KV:
			return &kvrwset.KVRWSet{}, nil
		default:
			return nil, fmt.Errorf("unknown data model type: %v", dnrws.DataModel)
		}
	default:
		return nil, fmt.Errorf("not a marshaled field: %s", name)
	}
}

func (dnrws *DynamicNsReadWriteSet) DynamicSliceFields() []string {
	if dnrws.DataModel != TxReadWriteSet_KV {
		// We only know how to handle TxReadWriteSet_KV types
		return []string{}
	}

	return []string{"collection_hashed_rwset"}
}

func (dnrws *DynamicNsReadWriteSet) DynamicSliceFieldProto(name string, index int, base proto.Message) (proto.Message, error) {
	if name != dnrws.DynamicSliceFields()[0] {
		return nil, fmt.Errorf("Not a dynamic field: %s", name)
	}

	chrws, ok := base.(*CollectionHashedReadWriteSet)
	if !ok {
		return nil, fmt.Errorf("NsReadWriteSet must embed a *CollectionHashedReadWriteSet its dynamic field")
	}

	return &DynamicCollectionHashedReadWriteSet{
		CollectionHashedReadWriteSet: chrws,
		DataModel:                    dnrws.DataModel,
	}, nil
}

type DynamicCollectionHashedReadWriteSet struct {
	*CollectionHashedReadWriteSet
	DataModel TxReadWriteSet_DataModel
}

func (dchrws *DynamicCollectionHashedReadWriteSet) Underlying() proto.Message {
	return dchrws.CollectionHashedReadWriteSet
}

func (dchrws *DynamicCollectionHashedReadWriteSet) StaticallyOpaqueFields() []string {
	return []string{"rwset"}
}

func (dchrws *DynamicCollectionHashedReadWriteSet) StaticallyOpaqueFieldProto(name string) (proto.Message, error) {
	switch name {
	case "rwset":
		switch dchrws.DataModel {
		case TxReadWriteSet_KV:
			return &kvrwset.HashedRWSet{}, nil
		default:
			return nil, fmt.Errorf("unknown data model type: %v", dchrws.DataModel)
		}
	default:
		return nil, fmt.Errorf("not a marshaled field: %s", name)
	}
}

// Remove removes the rwset for the given <ns, coll> tuple. If after this removal,
// there are no more collection in the namespace <ns>, the whole namespace entry is removed
func (p *TxPvtReadWriteSet) Remove(ns, coll string) {
	for i := 0; i < len(p.NsPvtRwset); i++ {
		n := p.NsPvtRwset[i]
		if n.Namespace != ns {
			continue
		}
		n.remove(coll)
		if len(n.CollectionPvtRwset) == 0 {
			p.NsPvtRwset = append(p.NsPvtRwset[:i], p.NsPvtRwset[i+1:]...)
		}
		return
	}
}

func (n *NsPvtReadWriteSet) remove(collName string) {
	for i := 0; i < len(n.CollectionPvtRwset); i++ {
		c := n.CollectionPvtRwset[i]
		if c.CollectionName != collName {
			continue
		}
		n.CollectionPvtRwset = append(n.CollectionPvtRwset[:i], n.CollectionPvtRwset[i+1:]...)
		return
	}
}
