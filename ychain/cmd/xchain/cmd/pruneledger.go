/*
 * Copyright (c) 2021, Baidu.com, Inc. All Rights Reserved.
 */

package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"path/filepath"

	"github.com/OpenAtomFoundation/xupercore/global/bcs/ledger/xledger/def"
	"github.com/OpenAtomFoundation/xupercore/global/bcs/ledger/xledger/ledger"
	"github.com/OpenAtomFoundation/xupercore/global/bcs/ledger/xledger/state"
	sctx "github.com/OpenAtomFoundation/xupercore/global/bcs/ledger/xledger/state/context"
	"github.com/OpenAtomFoundation/xupercore/global/bcs/ledger/xledger/xldgpb"
	"github.com/OpenAtomFoundation/xupercore/global/kernel/common/xconfig"
	"github.com/OpenAtomFoundation/xupercore/global/lib/crypto/client"
	"github.com/OpenAtomFoundation/xupercore/global/lib/logs"
	"github.com/OpenAtomFoundation/xupercore/global/lib/storage/kvdb"
	_ "github.com/OpenAtomFoundation/xupercore/global/lib/storage/kvdb/leveldb"
	"github.com/OpenAtomFoundation/xupercore/global/lib/utils"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/spf13/cobra"
)

// PruneLedgerCommand prune ledger  cmd
type PruneLedgerCommand struct {
	BaseCmd
	//链名
	Name string
	//裁剪到的目标区块链区块idr
	Target string
	// 环境配置文件
	EnvConf string
	// 加密类型
	Crypto string
}

// NewCreateChainVersion new create chain cmd
func GetPruneLedgerCommand() *PruneLedgerCommand {
	c := new(PruneLedgerCommand)
	c.Cmd = &cobra.Command{
		Use:   "pruneLedger",
		Short: "prune ledger to target block id.(Please stop node before prune ledger!)",
		RunE: func(cmd *cobra.Command, args []string) error {
			econf, err := c.genEnvConfig(c.EnvConf)
			if err != nil {
				return err
			}
			return c.pruneLedger(econf)
		},
	}

	c.Cmd.Flags().StringVarP(&c.Name,
		"name", "n", "xuper", "block chain name")
	c.Cmd.Flags().StringVarP(&c.Target,
		"target", "t", "", "target block id")
	c.Cmd.Flags().StringVarP(&c.EnvConf,
		"env_conf", "e", "./conf/env.yaml", "env config file path")
	c.Cmd.Flags().StringVarP(&c.Crypto,
		"crypto", "c", "default", "crypto type")

	return c
}

func (c *PruneLedgerCommand) pruneLedger(econf *xconfig.EnvConf) error {
	log.Printf("start prune ledger.bc_name:%s block_id:%s env_conf:%s\n",
		c.Name, c.Target, c.EnvConf)

	logs.InitLog(econf.GenConfFilePath(econf.LogConf), econf.GenDirAbsPath(econf.LogDir))
	lctx, err := ledger.NewLedgerCtx(econf, c.Name)
	if err != nil {
		return err
	}

	ledgerPath := lctx.EnvCfg.GenDataAbsPath(lctx.EnvCfg.ChainDir)
	ledgerPath = filepath.Join(ledgerPath, lctx.BCName)
	if !utils.PathExists(ledgerPath) {
		return errors.New("invalid name:" + lctx.BCName)
	}

	xledger, err := ledger.OpenLedger(lctx)
	if err != nil {
		return err
	}
	crypt, err := client.CreateCryptoClient(c.Crypto)
	if err != nil {
		return err
	}
	ctx, err := sctx.NewStateCtx(econf, c.Name, xledger, crypt)
	if err != nil {
		return err
	}
	shandle, err := state.NewState(ctx)
	if err != nil {
		return err
	}

	defer xledger.Close()
	defer shandle.Close()

	targetBlockId, err := hex.DecodeString(c.Target)
	if err != nil {
		return err
	}
	targetBlock, err := xledger.QueryBlock(targetBlockId)
	if err != nil {
		log.Printf("query target block error:%v", err)
		return err
	}
	// utxo 主干切换
	walkErr := shandle.Walk(targetBlockId, true)
	if walkErr != nil {
		log.Printf("pruneLedger walk targetBlockid error:%v", walkErr)
		return walkErr
	}
	// ledger 主干切换
	batch := xledger.GetLDB().NewBatch()
	_, splitErr := xledger.HandleFork(xledger.GetMeta().TipBlockid, targetBlockId, batch)
	if splitErr != nil {
		log.Printf("handle fork error:%v", splitErr)
		return splitErr
	}
	// ledger主干切换的扫尾工作
	newMeta := proto.Clone(xledger.GetMeta()).(*xldgpb.LedgerMeta)
	newMeta.TrunkHeight = targetBlock.Height
	newMeta.TipBlockid = targetBlock.Blockid
	metaBuf, pbErr := proto.Marshal(newMeta)
	if pbErr != nil {
		log.Printf("meta proto marshal error:%v", err)
		return pbErr
	}
	if err := batch.Put([]byte(xldgpb.MetaTablePrefix), metaBuf); err != nil {
		log.Printf("write meta error:%v", err)
		return err
	}

	// 剪掉所有无效分支
	pruneErr := pruneInvalidBranch(xledger, targetBlock, batch)
	if pruneErr != nil {
		return pruneErr
	}

	kvErr := batch.Write()
	if kvErr != nil {
		log.Printf("batch write error:%v", err)
		return kvErr
	}
	log.Printf("prune ledger success")
	return nil
}

// pruneInvalidBranch deletes invalid branch in batch according to target block
func pruneInvalidBranch(xLedger *ledger.Ledger, targetBlock *xldgpb.InternalBlock, batch kvdb.Batch) error {
	// step1: 获取所有无效分支
	branchHeadArr, branchErr := xLedger.GetBranchInfo(targetBlock.Blockid, targetBlock.Height)
	if branchErr != nil {
		log.Printf("pruneLedger GetTargetRangeBranchInfo error:%v", branchErr)
		return branchErr
	}

	// step2: 将无效分支剪掉
	for _, v := range branchHeadArr {
		// get common parent from higher to lower and truncate all of them
		commonParentBlockID, err := xLedger.GetCommonParentBlockid(targetBlock.Blockid, []byte(v))
		if err != nil && def.NormalizedKVError(err) != def.ErrKVNotFound && err != ledger.ErrBlockNotExist {
			log.Printf("get parent blockid error:%v", err)
			return err
		}
		err = xLedger.RemoveBlocks([]byte(v), commonParentBlockID, batch)
		if err != nil && def.NormalizedKVError(err) != def.ErrKVNotFound && err != ledger.ErrBlockNotExist {
			log.Printf("branch prune RemoveBlocks error:%v", err)
			return err
		}
		// 将无效分支头信息也删掉
		err = batch.Delete(append([]byte(xldgpb.BranchInfoPrefix), []byte(v)...))
		if err != nil {
			log.Printf("branchInfo batch delete error:%v", err)
			return err
		}
	}
	return nil
}

func (c *PruneLedgerCommand) genEnvConfig(path string) (*xconfig.EnvConf, error) {
	if !utils.FileIsExist(path) {
		log.Printf("config file not exist.env_conf:%s\n", c.EnvConf)
		return nil, fmt.Errorf("config file not exist")
	}

	econf, err := xconfig.LoadEnvConf(c.EnvConf)
	if err != nil {
		log.Printf("load env config failed.env_conf:%s err:%v\n", c.EnvConf, err)
		return nil, fmt.Errorf("load env config failed")
	}
	return econf, nil
}
