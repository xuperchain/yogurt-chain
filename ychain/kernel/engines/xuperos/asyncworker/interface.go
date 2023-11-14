package asyncworker

import "github.com/xuperchain/yogurt-chain/ychain/kernel/engines/xuperos/common"

type AsyncWorker interface {
	RegisterHandler(contract string, event string, handler func(ctx common.TaskContext) error)
}
