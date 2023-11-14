package propose

import (
	"fmt"

	"github.com/xuperchain/yogurt-chain/ychain/kernel/common/xcontext"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/contract"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/contract/proposal/utils"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/ledger"
	"github.com/xuperchain/yogurt-chain/ychain/lib/logs"
	"github.com/xuperchain/yogurt-chain/ychain/lib/timer"
)

type LedgerRely interface {
	// 获取状态机最新确认快照
	GetTipXMSnapshotReader() (ledger.XMSnapshotReader, error)
}

type ProposeCtx struct {
	// 基础上下文
	xcontext.BaseCtx
	BcName   string
	Ledger   LedgerRely
	Contract contract.Manager
}

func NewProposeCtx(bcName string, leg LedgerRely, contract contract.Manager) (*ProposeCtx, error) {
	if bcName == "" || leg == nil || contract == nil {
		return nil, fmt.Errorf("new propose ctx failed because param error")
	}

	log, err := logs.NewLogger("", utils.ProposalKernelContract)
	if err != nil {
		return nil, fmt.Errorf("new propose ctx failed because new logger error. err:%v", err)
	}

	ctx := new(ProposeCtx)
	ctx.XLog = log
	ctx.Timer = timer.NewXTimer()
	ctx.BcName = bcName
	ctx.Ledger = leg
	ctx.Contract = contract

	return ctx, nil
}
