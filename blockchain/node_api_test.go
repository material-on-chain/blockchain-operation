package blockchain

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/shopspring/decimal"
)

const (
	testNodeAPI  = ""
	testUser     = ""
	testPassword = ""
)

func Test_getBlockHeight(t *testing.T) {
	token := BasicAuth(testUser, testPassword)
	c := NewClient(testNodeAPI, token, true)

	r, err := c.getBlockHeight()

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("height:", r)
	}

}

func Test_getBlockByHeight(t *testing.T) {
	token := BasicAuth(testUser, testPassword)
	c := NewClient(testNodeAPI, token, true)
	r, err := c.getBlockByHeight(2430532)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}
}
func Test_getBlockByHash(t *testing.T) {
	hash := "3Uvb87ukKKwVeU6BFsZ21hy9sSbSd3Rd5QZTWbNop1d3TaY9ZzceJAT54vuY8XXQmw6nDx8ZViPV3cVznAHTtiVE"

	token := BasicAuth(testUser, testPassword)
	c := NewClient(testNodeAPI, token, true)

	r, err := c.Call("blocks/signature/"+hash, nil)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}
}

func Test_getBlockHash(t *testing.T) {
	token := BasicAuth(testUser, testPassword)
	c := NewClient(testNodeAPI, token, true)

	height := uint64(3075411)

	r, err := c.getBlockHash(height)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}

}

func Test_getBalance(t *testing.T) {
	token := BasicAuth(testUser, testPassword)
	c := NewClient(testNodeAPI, token, true)

	address := "WSgXFsGz5ZVEnTyDtEAhkdvtYMwj4Cfx99"

	r, err := c.getBalance(address)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}

	address = "WbP5WTty9jz6tAsAXwJMAinURp8Nznou7B"
	r, err = c.getBalance(address)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}

	address = "WkRxyJ7r3eqf8KeXs1F215XeucyHXbS8HX"
	r, err = c.getBalance(address)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}

}

func Test_getTransaction(t *testing.T) {
	token := BasicAuth(testUser, testPassword)
	c := NewClient(testNodeAPI, token, true)
	txid := "f41db24c8fbbf3c2540c63ad42bfee33474ac5e4f4b3656c2b5cc4e9c1f0cebd" //"9KBoALfTjvZLJ6CAuJCGyzRA1aWduiNFMvbqTchfBVpF"

	r, err := c.getTransaction(txid)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}

	txid = "1b0147a6b5660215e9a37ca34fe9a6298988e45f7eefbd8c4b98993f4e762c3e" //"9KBoALfTjvZLJ6CAuJCGyzRA1aWduiNFMvbqTchfBVpF"

	r, err = c.getTransaction(txid)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}

	txid = "3ca0888b232df90d910a921d2f4004bb61a80bbbe27caee7107de282576e38a0" //"9KBoALfTjvZLJ6CAuJCGyzRA1aWduiNFMvbqTchfBVpF"

	r, err = c.getTransaction(txid)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}
}

func Test_convert(t *testing.T) {

	amount := uint64(5000000001)

	amountStr := fmt.Sprintf("%d", amount)

	fmt.Println(amountStr)

	d, _ := decimal.NewFromString(amountStr)

	w, _ := decimal.NewFromString("100000000")

	d = d.Div(w)

	fmt.Println(d.String())

	d = d.Mul(w)

	fmt.Println(d.String())

	r, _ := strconv.ParseInt(d.String(), 10, 64)

	fmt.Println(r)

	fmt.Println(time.Now().UnixNano())
}

func Test_getTransactionByAddresses(t *testing.T) {
	addrs := "ARAA8AnUYa4kWwWkiZTTyztG5C6S9MFTx11"

	token := BasicAuth(testUser, testPassword)
	c := NewClient(testNodeAPI, token, true)
	result, err := c.getMultiAddrTransactions(0, -1, addrs)

	if err != nil {
		t.Error("get transactions failed!")
	} else {
		for _, tx := range result {
			fmt.Println(tx.TxID)
		}
	}
}
