package main

import (
	"fmt"
	"log"

	"github.com/xuperchain/yogurt-chain/ychain/cmd/client/cmd"
)

var (
	Version   = ""
	BuildTime = ""
	CommitID  = ""
)

func main() {
	cli := cmd.NewCli()
	cli.SetVer(printVersion())

	err := cli.Init()
	if err != nil {
		log.Fatal(err)
	}

	cli.AddCommands(cmd.Commands)
	cli.Execute()
}

func printVersion() string {
	return fmt.Sprintf("%s-%s %s\n", Version, CommitID, BuildTime)
}
