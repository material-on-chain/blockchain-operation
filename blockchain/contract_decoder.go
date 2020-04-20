package blockchain

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/blocktree/openwallet/log"
	"github.com/blocktree/openwallet/openwallet"
	"github.com/shopspring/decimal"
)

type AddrBalance struct {
	Address      string
	Balance      *big.Int
	TokenBalance *big.Int
	index        int
	Registered   bool
	UserID       string
}

func convertFlostStringToBigInt(amount string) (*big.Int, error) {
	vDecimal, err := decimal.NewFromString(amount)
	if err != nil {
		log.Error("convert from string to decimal failed, err=", err)
		return nil, err
	}

	decimalInt := big.NewInt(1)
	for i := 0; i < 9; i++ {
		decimalInt.Mul(decimalInt, big.NewInt(10))
	}
	d, _ := decimal.NewFromString(decimalInt.String())
	vDecimal = vDecimal.Mul(d)
	rst := new(big.Int)
	if _, valid := rst.SetString(vDecimal.String(), 10); !valid {
		log.Error("conver to big.int failed")
		return nil, errors.New("conver to big.int failed")
	}
	return rst, nil
}

func convertBigIntToFloatDecimal(amount string) (decimal.Decimal, error) {
	d, err := decimal.NewFromString(amount)
	if err != nil {
		log.Error("convert string to deciaml failed, err=", err)
		return d, err
	}

	decimalInt := big.NewInt(1)
	for i := 0; i < 9; i++ {
		decimalInt.Mul(decimalInt, big.NewInt(10))
	}

	w, _ := decimal.NewFromString(decimalInt.String())
	d = d.Div(w)
	return d, nil
}

func convertIntStringToBigInt(amount string) (*big.Int, error) {
	vInt64, err := strconv.ParseInt(amount, 10, 64)
	if err != nil {
		log.Error("convert from string to int failed, err=", err)
		return nil, err
	}

	return big.NewInt(vInt64), nil
}

type ContractDecoder struct {
	*openwallet.SmartContractDecoderBase
	wm *WalletManager
}

//NewContractDecoder 智能合约解析器
func NewContractDecoder(wm *WalletManager) *ContractDecoder {
	decoder := ContractDecoder{}
	decoder.wm = wm
	return &decoder
}

func convertToAmountWithDecimal(amount, decimals uint64) string {
	amountStr := fmt.Sprintf("%d", amount)
	d, _ := decimal.NewFromString(amountStr)
	decimalStr := "1"
	for index := 0; index < int(decimals); index++ {
		decimalStr += "0"
	}
	w, _ := decimal.NewFromString(decimalStr)
	d = d.Div(w)
	return d.String()
}

func convertFromAmountWithDecimal(amountStr string, decimals uint64) uint64 {
	d, _ := decimal.NewFromString(amountStr)
	decimalsStr := "1"
	for i := uint64(0); i < decimals; i ++ {
		decimalsStr += "0"
	}
	w, _ := decimal.NewFromString(decimalsStr)

	d = d.Mul(w)

	r, _ := strconv.ParseInt(d.String(), 10, 64)
	return uint64(r)

}


func (decoder *ContractDecoder) GetTokenBalanceByAddress(contract openwallet.SmartContract, address ...string) ([]*openwallet.TokenBalance, error) {
	var tokenBalanceList []*openwallet.TokenBalance

	for i := 0; i < len(address); i++ {
		tokenBalance := openwallet.TokenBalance{
			Contract: &contract,
		}

		balance, err := decoder.wm.Client.getContractAccountBalence(contract.Address, address[i])
		if err != nil {
			return nil, err
		}

		balanceUint, _ := strconv.ParseUint(balance.TokenBalance.String(), 10, 64)
		tokenBalance.Balance = &openwallet.Balance{
			Address:          address[i],
			Symbol:           contract.Symbol,
			Balance:          convertToAmountWithDecimal(balanceUint, contract.Decimals),
			ConfirmBalance:   convertToAmountWithDecimal(balanceUint, contract.Decimals),
			UnconfirmBalance: "0",
		}

		tokenBalanceList = append(tokenBalanceList, &tokenBalance)
	}

	return tokenBalanceList, nil
}

const (
	WRC20Magic byte = 0xf0
	WRC20Methd byte = 0x16
)

func genWRC20Param(to string, amount uint64) ([]byte, error) {
	if !IsValid(to) {
		return nil, openwallet.Errorf(openwallet.ErrAdressDecodeFailed, "[%s] Invalid address to send!", to)
	}
	ret := make([]byte, 0)
	ret = append(ret, WRC20Magic, WRC20Methd)
	ret = append(ret, 0x00, 0x00) // reserved
	ret = append(ret, []byte(to)...)
	amountBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(amountBytes, amount)
	ret = append(ret, amountBytes...)
	return ret, nil
}

type WRC20Token struct {
	TokenSymbol string
	TokenRegID  string
}

func NewWRC20Tokens(data string) []WRC20Token {
	if data == "" {
		return nil
	}
	var ret []WRC20Token
	data = strings.Replace(data, " ", "", -1)
	tokensStr := strings.Split(data, ",")

	for _, str := range tokensStr {
		strs := strings.Split(str, "@")
		ret = append(ret, WRC20Token{TokenSymbol: strs[0], TokenRegID: strs[1]})
	}
	return ret
}

func (decoder *ContractDecoder) isWRC20Token(id, arg string) (bool, string, string) {

	address, amount := getDestAddressAndAmountFromWrc20Args(arg)
	if address == "" {
		return false, "", ""
	}
	return true, address, amount

}

func getDestAddressAndAmountFromWrc20Args(arg string) (string, string) {
	argBytes, err := hex.DecodeString(arg)
	if err != nil || len(argBytes) != 46 {
		return "", ""
	}
	if argBytes[0] != 0xf0 || argBytes[1] != 0x16 || argBytes[2] != 0x00 || argBytes[3] != 0x00 {
		return "", ""
	}

	return string(argBytes[4:38]), strconv.FormatUint(binary.LittleEndian.Uint64(argBytes[38:]), 10)
}
