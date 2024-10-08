/*
 * Copyright (c) 2021. Baidu Inc. All Rights Reserved.
 */

package cmd

import (
	"context"
	"io/ioutil"

	"github.com/spf13/cobra"

	"github.com/OpenAtomFoundation/xupercore/global/bcs/ledger/xledger/state/utxo"
)

// ContractUpgradeCommand wasm upgrade cmd
type ContractUpgradeCommand struct {
	cli *Cli
	cmd *cobra.Command

	account      string
	contractName string
	fee          string
	isMulti      bool
	multiAddrs   string
	output       string
}

// NewContractUpgradeCommand new wasm deploy cmd
func NewContractUpgradeCommand(cli *Cli) *cobra.Command {
	c := new(ContractUpgradeCommand)
	c.cli = cli
	c.cmd = &cobra.Command{
		Use:   "upgrade [options] code path",
		Short: "upgrade contract code",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.TODO()
			return c.upgrade(ctx, args[0])
		},
	}
	c.addFlags()
	return c.cmd
}

func (c *ContractUpgradeCommand) addFlags() {
	c.cmd.Flags().StringVarP(&c.contractName, "cname", "n", "", "contract name")
	c.cmd.Flags().StringVarP(&c.account, "account", "", "", "account name")
	c.cmd.Flags().StringVar(&c.fee, "fee", "", "fee of one tx")
	c.cmd.Flags().BoolVarP(&c.isMulti, "isMulti", "m", false, "multisig scene")
	c.cmd.Flags().StringVarP(&c.multiAddrs, "multiAddrs", "A", "data/acl/addrs", "multiAddrs if multisig scene")
	c.cmd.Flags().StringVarP(&c.output, "output", "o", "./tx.out", "tx draw data")
}

func (c *ContractUpgradeCommand) upgrade(ctx context.Context, codepath string) error {
	ct := &CommTrans{
		Amount:       "0",
		Fee:          c.fee,
		FrozenHeight: 0,
		Version:      utxo.TxVersion,
		ModuleName:   "xkernel",
		ContractName: "$contract",
		MethodName:   "upgradeContract",
		Args:         make(map[string][]byte),
		MultiAddrs:   c.multiAddrs,
		From:         c.account,
		Output:       c.output,
		IsQuick:      c.isMulti,
		ChainName:    c.cli.RootOptions.Name,
		Keys:         c.cli.RootOptions.Keys,
		XchainClient: c.cli.XchainClient(),
		CryptoType:   c.cli.RootOptions.Crypto,
		RootOptions:  c.cli.RootOptions,
	}

	var err error
	ct.To, err = readAddress(ct.Keys)
	if err != nil {
		return err
	}

	codebuf, err := ioutil.ReadFile(codepath)
	if err != nil {
		return err
	}
	ct.Args = map[string][]byte{
		"contract_name": []byte(c.contractName),
		"contract_code": codebuf,
	}

	if c.isMulti {
		err = ct.GenerateMultisigGenRawTx(ctx)
	} else {
		err = ct.Transfer(ctx)
	}

	return err
}
