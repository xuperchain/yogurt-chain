package bridge

import (
	"github.com/xuperchain/yogurt-chain/ychain/kernel/contract"
	"github.com/xuperchain/yogurt-chain/ychain/protos"
)

func eventsResourceUsed(events []*protos.ContractEvent) contract.Limits {
	var size int64
	for _, event := range events {
		size += int64(len(event.Contract) + len(event.Name) + len(event.Body))
	}
	return contract.Limits{
		Disk: size,
	}
}
