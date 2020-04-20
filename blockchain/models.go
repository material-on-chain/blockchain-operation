/*
 * Copyright 2018 The openwallet Authors
 * This file is part of the openwallet library.
 *
 * The openwallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The openwallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

package blockchain

import (
	"fmt"

	"github.com/blocktree/go-owcdrivers/waykichainTransaction"
	"github.com/blocktree/openwallet/crypto"
	"github.com/blocktree/openwallet/openwallet"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tidwall/gjson"
)

// type Vin struct {
// 	Coinbase string
// 	TxID     string
// 	Vout     uint64
// 	N        uint64
// 	Addr     string
// 	Value    string
// }

// type Vout struct {
// 	N            uint64
// 	Addr         string
// 	Value        string
// 	ScriptPubKey string
// 	Type         string
// }

type Block struct {

	/*
		{
		    "hash":"d72bd1aaa10d47ee68eedcc1e9b99e8d097d93a9a05e0f683456ff1ad72ba846",
		    "confirmations":1,
		    "size":177,
		    "height":2430532,
		    "version":1,
		    "merkleroot":"f41db24c8fbbf3c2540c63ad42bfee33474ac5e4f4b3656c2b5cc4e9c1f0cebd",
		    "txnumber":1,
		    "tx":
		    [
		        "f41db24c8fbbf3c2540c63ad42bfee33474ac5e4f4b3656c2b5cc4e9c1f0cebd"
		    ],
		    "time":1554106110,
		    "nonce":426,
		    "chainwork":"0000000000000000000000000000000000000000000000000000000000251644",
		    "fuel":0,
		    "fuelrate":1,
		    "previousblockhash":"8fc83042ba76bf893d58407704fa73b65dba8484c1b07e282dbf31a89ead507b"
		}
	*/

	Hash                  string // actually block signature in WICC chain
	Size                  uint64
	Version               byte
	PrevBlockHash         string // actually block signature in WICC chain
	TransactionMerkleRoot string
	Timestamp             uint64
	Height                uint64
	Transactions          []string
}

type Transaction struct {
	TxType          byte
	TxID            string
	Fee             uint64
	TimeStamp       uint64
	From            string
	To              string
	Amount          uint64
	BlockHeight     uint64
	BlockHash       string
	Confirmedheight uint64
	Wrc20RegID      string
	Wrc20Args       string
}

func NewTransaction(json *gjson.Result) *Transaction {
	obj := &Transaction{}
	switch json.Get("tx_type").String() {
	case "BLOCK_REWARD_TX":
		{
			obj.TxType = waykichainTransaction.TxType_REWARD
			obj.To = json.Get("to_addr").String()
			obj.Amount = json.Get("reward_fees").Uint()
		}
		break
	case "ACCOUNT_REGISTER_TX":
		{
			obj.TxType = waykichainTransaction.TxType_REGACCT
			obj.From = json.Get("from_addr").String()
			if json.Get("fee_symbol").String() == "WICC" {
				obj.Amount = json.Get("fees").Uint()
			}
		}
		break
	case "BCOIN_TRANSFER_TX","UCOIN_TRANSFER_TX":
		{
			obj.TxType = waykichainTransaction.TxType_COMMON
			obj.From = json.Get("from_addr").String()

			tos := json.Get("transfers").Array()

			for _, to := range tos {
				if to.Get("coin_symbol").String() == "WICC" {
					obj.To = to.Get("to_addr").String()
					obj.Amount = to.Get("coin_amount").Uint()
				}
			}

			if json.Get("fee_symbol").String() == "WICC" {
				obj.Fee = json.Get("fees").Uint()
			}
		}
		break
	case "LCONTRACT_INVOKE_TX":
		{
			obj.TxType = waykichainTransaction.TxType_CONTRACT
			obj.From = json.Get("from_addr").String()
			obj.To = json.Get("to_addr").String()
			if json.Get("fee_symbol").String() == "WICC" {
				obj.Fee = json.Get("fees").Uint()
			}
			obj.Wrc20RegID = json.Get("to_uid").String()
			obj.Wrc20Args = json.Get("arguments").String()
		}
		break
	default:
		{
			return obj
		}
	}
	obj.TxID = json.Get("txid").String()
	obj.BlockHash = json.Get("block_hash").String()
	obj.BlockHeight = json.Get("valid_height").Uint()
	obj.TimeStamp = json.Get("confirmed_time").Uint()
	obj.Confirmedheight = json.Get("confirmed_height").Uint()

	return obj
}

func NewBlock(json *gjson.Result) *Block {

	obj := &Block{}
	/*
		{
		    "hash":"d72bd1aaa10d47ee68eedcc1e9b99e8d097d93a9a05e0f683456ff1ad72ba846",
		    "confirmations":1,
		    "size":177,
		    "height":2430532,
		    "version":1,
		    "merkleroot":"f41db24c8fbbf3c2540c63ad42bfee33474ac5e4f4b3656c2b5cc4e9c1f0cebd",
		    "txnumber":1,
		    "tx":
		    [
		        "f41db24c8fbbf3c2540c63ad42bfee33474ac5e4f4b3656c2b5cc4e9c1f0cebd"
		    ],
		    "time":1554106110,
		    "nonce":426,
		    "chainwork":"0000000000000000000000000000000000000000000000000000000000251644",
		    "fuel":0,
		    "fuelrate":1,
		    "previousblockhash":"8fc83042ba76bf893d58407704fa73b65dba8484c1b07e282dbf31a89ead507b"
		}
	*/
	// 解析
	obj.Hash = gjson.Get(json.Raw, "block_hash").String()
	obj.Size = gjson.Get(json.Raw, "size").Uint()
	obj.Version = byte(gjson.Get(json.Raw, "version").Uint())
	obj.PrevBlockHash = gjson.Get(json.Raw, "previous_block_hash").String()
	obj.TransactionMerkleRoot = gjson.Get(json.Raw, "merkle_root").String()
	obj.Timestamp = gjson.Get(json.Raw, "time").Uint()
	obj.Height = gjson.Get(json.Raw, "height").Uint()

	txs := gjson.Get(json.Raw, "tx").Array()

	for _, tx := range txs {
		obj.Transactions = append(obj.Transactions, tx.String())
	}

	return obj
}

//BlockHeader 区块链头
func (b *Block) BlockHeader() *openwallet.BlockHeader {

	obj := openwallet.BlockHeader{}
	//解析json
	obj.Hash = b.Hash
	//obj.Confirmations = b.Confirmations
	obj.Merkleroot = b.TransactionMerkleRoot
	obj.Previousblockhash = b.PrevBlockHash
	obj.Height = b.Height
	obj.Version = uint64(b.Version)
	obj.Time = b.Timestamp
	obj.Symbol = Symbol

	return &obj
}

//UnscanRecords 扫描失败的区块及交易
type UnscanRecord struct {
	ID          string `storm:"id"` // primary key
	BlockHeight uint64
	TxID        string
	Reason      string
}

func NewUnscanRecord(height uint64, txID, reason string) *UnscanRecord {
	obj := UnscanRecord{}
	obj.BlockHeight = height
	obj.TxID = txID
	obj.Reason = reason
	obj.ID = common.Bytes2Hex(crypto.SHA256([]byte(fmt.Sprintf("%d_%s", height, txID))))
	return &obj
}
