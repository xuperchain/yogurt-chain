package mock

import (
	"path/filepath"

	xconf "github.com/xuperchain/yogurt-chain/ychain/kernel/common/xconfig"
	"github.com/xuperchain/yogurt-chain/ychain/lib/logs"
	"github.com/xuperchain/yogurt-chain/ychain/lib/utils"
)

func NewEnvConfForTest(paths ...string) (*xconf.EnvConf, error) {
	path := "conf/env.yaml"
	if len(paths) > 0 {
		path = paths[0]
	}

	dir := utils.GetCurFileDir()
	econfPath := filepath.Join(dir, path)
	econf, err := xconf.LoadEnvConf(econfPath)
	if err != nil {
		return nil, err
	}

	econf.RootPath = utils.GetCurFileDir()
	logs.InitLog(econf.GenConfFilePath(econf.LogConf), econf.GenDirAbsPath(econf.LogDir))
	return econf, nil
}