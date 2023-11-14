package xuperos

import (
	"fmt"
	"log"
	"os"
	"testing"

	// import要使用的内核核心组件驱动
	_ "github.com/xuperchain/yogurt-chain/ychain/bcs/consensus/tdpos"
	_ "github.com/xuperchain/yogurt-chain/ychain/bcs/contract/evm"
	_ "github.com/xuperchain/yogurt-chain/ychain/bcs/contract/native"
	_ "github.com/xuperchain/yogurt-chain/ychain/bcs/contract/xvm"
	_ "github.com/xuperchain/yogurt-chain/ychain/bcs/network/p2pv1"
	_ "github.com/xuperchain/yogurt-chain/ychain/bcs/network/p2pv2"
	_ "github.com/xuperchain/yogurt-chain/ychain/kernel/contract/kernel"
	_ "github.com/xuperchain/yogurt-chain/ychain/kernel/contract/manager"
	_ "github.com/xuperchain/yogurt-chain/ychain/lib/crypto/client"
	_ "github.com/xuperchain/yogurt-chain/ychain/lib/storage/kvdb/leveldb"

	xledger "github.com/xuperchain/yogurt-chain/ychain/bcs/ledger/xledger/utils"
	xconf "github.com/xuperchain/yogurt-chain/ychain/kernel/common/xconfig"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/engines/xuperos/common"
	"github.com/xuperchain/yogurt-chain/ychain/kernel/mock"
)

func CreateLedger(conf *xconf.EnvConf) error {
	mockConf, err := mock.NewEnvConfForTest()
	if err != nil {
		return fmt.Errorf("new mock env conf error: %v", err)
	}

	genesisPath := mockConf.GenDataAbsPath("genesis/xuper.json")
	err = xledger.CreateLedger("xuper", genesisPath, conf)
	if err != nil {
		log.Printf("create ledger failed.err:%v\n", err)
		return fmt.Errorf("create ledger failed")
	}
	return nil
}

func RemoveLedger(conf *xconf.EnvConf) {
	path := conf.GenDataAbsPath("blockchain")
	if err := os.RemoveAll(path); err != nil {
		log.Printf("remove ledger failed.err:%v\n", err)
	}
}

func MockEngine(path string) (common.Engine, error) {
	conf, err := mock.NewEnvConfForTest(path)
	if err != nil {
		return nil, fmt.Errorf("new env conf error: %v", err)
	}

	RemoveLedger(conf)
	if err = CreateLedger(conf); err != nil {
		return nil, err
	}

	engine := NewEngine()
	if err := engine.Init(conf); err != nil {
		return nil, fmt.Errorf("init engine error: %v", err)
	}

	eng, err := EngineConvert(engine)
	if err != nil {
		return nil, fmt.Errorf("engine convert error: %v", err)
	}

	return eng, nil
}

func TestEngine(t *testing.T) {
	_, err := MockEngine("p2pv2/node1/conf/env.yaml")
	if err != nil {
		t.Logf("%v", err)
		return
	}
	// go engine.Run()
	// engine.Exit()
}