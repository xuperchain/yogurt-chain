package common

import (
	"github.com/xuperchain/yogurt-chain/ychain/bcs/ledger/xledger/ledger"
	"github.com/xuperchain/yogurt-chain/ychain/bcs/ledger/xledger/state"
	lpb "github.com/xuperchain/yogurt-chain/ychain/bcs/ledger/xledger/xldgpb"
	xconf "github.com/xuperchain/yogurt-chain/ychain/kernel/common/xconfig"
	xctx "github.com/xuperchain/yogurt-chain/ychain/kernel/common/xcontext"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/consensus"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/contract"
	governToken "github.com/xuperchain/yogurt-chain/ychain/kernel/contract/proposal/govern_token"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/contract/proposal/propose"
	timerTask "github.com/xuperchain/yogurt-chain/ychain/kernel/contract/proposal/timer"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/engines"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/engines/xuperos/xtoken/base"
	kledger "github.com/xuperchain/yogurt-chain/ychain/kernel/ledger"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/network"
	aclBase "github.com/xuperchain/yogurt-chain/ychain/kernel/permission/acl/base"
	cryptoBase "github.com/xuperchain/yogurt-chain/ychain/lib/crypto/client/base"
	"github.com/xuperchain/yogurt-chain/ychain/protos"
)

type Chain interface {
	// 获取链上下文
	Context() *ChainCtx
	// 启动链
	Start()
	// 关闭链
	Stop()
	// 合约预执行
	PreExec(xctx.XContext, []*protos.InvokeRequest, string, []string) (*protos.InvokeResponse, error)
	// 提交交易
	SubmitTx(xctx.XContext, *lpb.Transaction) error
	// 处理新区块
	ProcBlock(xctx.XContext, *lpb.InternalBlock) error
	// 设置依赖实例化代理
	SetRelyAgent(ChainRelyAgent) error
}

// 定义xuperos引擎对外暴露接口
// 依赖接口而不是依赖具体实现
type Engine interface {
	engines.BCEngine
	ChainManager
	Context() *EngineCtx
	SetRelyAgent(EngineRelyAgent) error
}

// 定义引擎对各组件依赖接口约束
type EngineRelyAgent interface {
	CreateNetwork(*xconf.EnvConf) (network.Network, error)
}

// 定义链对各组件依赖接口约束
type ChainRelyAgent interface {
	CreateLedger() (*ledger.Ledger, error)
	CreateState(*ledger.Ledger, cryptoBase.CryptoClient) (*state.State, error)
	CreateContract(kledger.XMReader) (contract.Manager, error)
	CreateConsensus() (consensus.PluggableConsensusInterface, error)
	CreateCrypto(cryptoType string) (cryptoBase.CryptoClient, error)
	CreateAcl() (aclBase.AclManager, error)
	CreateGovernToken() (governToken.GovManager, error)
	CreateProposal() (propose.ProposeManager, error)
	CreateTimerTask() (timerTask.TimerManager, error)
	CreateXToken() (base.XTokenManager, error)
	CreateXRandom() error
}

type ChainManager interface {
	Get(string) (Chain, error)
	GetChains() []string
	LoadChain(string) error
	Stop(string) error
}

// 避免循环调用
type AsyncworkerAgent interface {
	RegisterHandler(contract string, event string, handler TaskHandler)
}

type TaskHandler func(ctx TaskContext) error

type TaskContext interface {
	// ParseArgs 用来解析任务参数，参数为对应任务参数类型的指针
	ParseArgs(v interface{}) error
	RetryTimes() int
}
