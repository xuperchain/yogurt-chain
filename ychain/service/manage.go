package service

import (
	"fmt"

	"github.com/OpenAtomFoundation/xupercore/global/kernel/engines"
	"github.com/OpenAtomFoundation/xupercore/global/lib/logs"

	scom "github.com/OpenAtomFoundation/xupercore/global/service/common"
	sconf "github.com/OpenAtomFoundation/xupercore/global/service/config"
	gw "github.com/OpenAtomFoundation/xupercore/global/service/gateway"
	"github.com/OpenAtomFoundation/xupercore/global/service/rpc"
)

// 由于需要同时启动多个服务组件，采用注册机制管理
type ServCom interface {
	Run() error
	Exit()
}

// 各server组件运行控制
type ServMG struct {
	scfg    *sconf.ServConf
	log     logs.Logger
	servers []ServCom
}

func NewServMG(scfg *sconf.ServConf, engine engines.BCEngine) (*ServMG, error) {
	if scfg == nil || engine == nil {
		return nil, fmt.Errorf("param error")
	}

	log, _ := logs.NewLogger("", scom.SubModName)
	obj := &ServMG{
		scfg:    scfg,
		log:     log,
		servers: make([]ServCom, 0),
	}

	// 实例化rpc服务
	serv, err := rpc.NewRpcServMG(scfg, engine)
	if err != nil {
		return nil, err
	}
	GW, err := gw.NewGateway(scfg)
	if err != nil {
		return nil, err
	}

	obj.servers = append(obj.servers, serv, GW)

	return obj, nil
}

// 启动rpc服务
func (t *ServMG) Run() error {
	ch := make(chan error)
	defer close(ch)

	for _, serv := range t.servers {
		// 启动各个service
		go func(s ServCom) {
			ch <- s.Run()
		}(serv)
	}

	// 监听各个service状态
	exitCnt := 0
	for {
		if exitCnt >= len(t.servers) {
			break
		}

		err := <-ch
		t.log.Warn("service exit", "err", err)
		exitCnt++
	}

	return nil
}

// 退出rpc服务，释放相关资源，需要幂等
func (t *ServMG) Exit() {
	for _, serv := range t.servers {
		// 触发各service退出
		go func(s ServCom) {
			s.Exit()
		}(serv)
	}
}
