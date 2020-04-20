package openwtester

import (
	"github.com/blocktree/openwallet/log"
	"github.com/blocktree/openwallet/openw"
	"github.com/material-on-chain/blockchain-operation/blockchain"
)

func init() {
	//注册钱包管理工具
	log.Notice("Wallet Manager Load Successfully.")
	openw.RegAssets(blockchain.Symbol, blockchain.NewWalletManager())
}
