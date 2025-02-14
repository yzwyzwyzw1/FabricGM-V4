/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clilogging

import (
	"fmt"

	"github.com/chinaso/fabricGM/common/flogging"
	"github.com/chinaso/fabricGM/peer/common"
	"github.com/spf13/cobra"
)

const (
	loggingFuncName = "logging"
	loggingCmdDes   = "Logging configuration: getlevel|setlevel|getlogspec|setlogspec|revertlevels."
)

var logger = flogging.MustGetLogger("cli.logging")

// Cmd returns the cobra command for Logging
func Cmd(cf *LoggingCmdFactory) *cobra.Command {
	loggingCmd.AddCommand(getLevelCmd(cf))
	loggingCmd.AddCommand(setLevelCmd(cf))
	loggingCmd.AddCommand(revertLevelsCmd(cf))
	loggingCmd.AddCommand(getLogSpecCmd(cf))
	loggingCmd.AddCommand(setLogSpecCmd(cf))

	return loggingCmd
}

var loggingCmd = &cobra.Command{
	Use:              loggingFuncName,
	Short:            fmt.Sprint(loggingCmdDes),
	Long:             fmt.Sprint(loggingCmdDes),
	PersistentPreRun: common.InitCmd,
}
