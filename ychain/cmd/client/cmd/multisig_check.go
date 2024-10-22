/*
 * Copyright (c) 2021. Baidu Inc. All Rights Reserved.
 */

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/spf13/cobra"

	"github.com/OpenAtomFoundation/xupercore/global/service/pb"
)

// MultisigCheckCommand multisig check struct
type MultisigCheckCommand struct {
	cli *Cli
	cmd *cobra.Command

	input  string
	output string
}

// NewMultisigCheckCommand multisig check init method
func NewMultisigCheckCommand(cli *Cli) *cobra.Command {
	c := &MultisigCheckCommand{}
	c.cli = cli
	c.cmd = &cobra.Command{
		Use:   "check",
		Short: "Check the raw transaction generated by the command of multisig gen.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.check()
		},
	}
	c.addFlags()
	return c.cmd
}

func (c *MultisigCheckCommand) addFlags() {
	c.cmd.Flags().StringVarP(&c.input, "input", "i", "./tx.out", "Serialized transaction data file.")
	c.cmd.Flags().StringVarP(&c.output, "output", "o", "./visualtx.out", "Readable transaction data file.")
}

// check 命令的主入口
func (c *MultisigCheckCommand) check() error {
	data, err := ioutil.ReadFile(c.input)
	if err != nil {
		return err
	}
	tx := &pb.Transaction{}
	err = proto.Unmarshal(data, tx)
	if err != nil {
		return err
	}

	// print tx
	t := FromPBTx(tx)
	output, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(output))
	err = ioutil.WriteFile(c.output, output, 0755)
	if err != nil {
		return errors.New("Write visual file error")
	}

	return nil
}
