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
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/blocktree/openwallet/log"
	"github.com/imroc/req"
	"github.com/tidwall/gjson"
)

type ClientInterface interface {
	Call(path string, request []interface{}) (*gjson.Result, error)
}

// A Client is a Elastos RPC client. It performs RPCs over HTTP using JSON
// request and responses. A Client must be configured with a secret token
// to authenticate with other Cores on the network.
type Client struct {
	BaseURL     string
	AccessToken string
	Debug       bool
	client      *req.Req
	//Client *req.Req
}

type Response struct {
	Code    int         `json:"code,omitempty"`
	Error   interface{} `json:"error,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Message string      `json:"message,omitempty"`
	Id      string      `json:"id,omitempty"`
}

func NewClient(url string, token string, debug bool) *Client {
	c := Client{
		BaseURL:     url,
		AccessToken: token,
		Debug:       debug,
	}

	api := req.New()
	//trans, _ := api.Client().Transport.(*http.Transport)
	//trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	c.client = api

	return &c
}

// Call calls a remote procedure on another node, specified by the path.
func (c *Client) Call(path string, request []interface{}) (*gjson.Result, error) {

	var (
		body = make(map[string]interface{}, 0)
	)

	if c.client == nil {
		return nil, errors.New("API url is not setup. ")
	}

	authHeader := req.Header{
		"Accept":        "application/json",
		"Authorization": "Basic " + c.AccessToken,
	}

	//json-rpc
	body["jsonrpc"] = "2.0"
	body["id"] = "curltext"
	body["method"] = path
	body["params"] = request

	if c.Debug {
		log.Std.Info("Start Request API...")
	}

	r, err := c.client.Post(c.BaseURL, req.BodyJSON(&body), authHeader)

	if c.Debug {
		log.Std.Info("Request API Completed")
	}

	if c.Debug {
		log.Std.Info("%+v", r)
	}

	if err != nil {
		return nil, err
	}

	resp := gjson.ParseBytes(r.Bytes())
	err = isError(&resp)
	if err != nil {
		return nil, err
	}

	result := resp.Get("result")

	return &result, nil
}

// See 2 (end of page 4) http://www.ietf.org/rfc/rfc2617.txt
// "To receive authorization, the client sends the userid and password,
// separated by a single colon (":") character, within a base64
// encoded string in the credentials."
// It is not meant to be urlencoded.
func BasicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))

	//return username + ":" + password
}

//isError 是否报错
func isError(result *gjson.Result) error {
	var (
		err error
	)

	/*
		//failed 返回错误
		{
			"result": null,
			"error": {
				"code": -8,
				"message": "Block height out of range"
			},
			"id": "foo"
		}
	*/

	if !result.Get("error").IsObject() {

		if !result.Get("result").Exists() {
			return errors.New("Response is empty! ")
		}

		return nil
	}

	errInfo := fmt.Sprintf("[%d]%s",
		result.Get("error.code").Int(),
		result.Get("error.message").String())
	err = errors.New(errInfo)

	return err
}

// 获取当前区块高度
func (c *Client) getBlockHeight() (uint64, error) {
	resp, err := c.Call("getblockcount", nil)

	if err != nil {
		return 0, err
	}

	return resp.Uint(), nil
}

// 通过高度获取区块哈希
func (c *Client) getBlockHash(height uint64) (string, error) {

	path := "getblock"
	request := []interface{}{
		height,
	}
	resp, err := c.Call(path, request)

	if err != nil {
		return "", err
	}

	return resp.Get("block_hash").String(), nil
}

// 获取地址余额
func (c *Client) getBalance(address string) (*AddrBalance, error) {
	path := "getaccountinfo"

	request := []interface{}{
		address,
	}

	r, err := c.Call(path, request)

	if err != nil {
		return nil, err
	}

	if r.Raw == "{}" || r.Get("regid").String() == "" {
		return &AddrBalance{Address: address, Balance:  big.NewInt(r.Get("tokens").Get("WICC").Get("free_amount").Int()), Registered: false}, nil
	}

	return &AddrBalance{Address: address, Balance: big.NewInt(r.Get("tokens").Get("WICC").Get("free_amount").Int()), Registered: true, UserID: r.Get("regid").String()}, nil
}

func (c *Client) isAddressRegistered(address string) bool {
	path := "getaccountinfo"

	request := []interface{}{
		address,
	}

	r, _ := c.Call(path, request)

	if r.Raw == "{}" || r.Get("regid").String() == "" {
		return false
	}
	return true
}

func (c *Client) getRegID(address string) (string, error) {
	path := "getaccountinfo"

	request := []interface{}{
		address,
	}

	r, err := c.Call(path, request)

	if err != nil {
		return "", err
	}
	if r.Raw == "{}" || r.Get("regid").String() == "" {
		return "", errors.New("Account: [" + address + "] has not been registered!")
	}
	return r.Get("regid").String(), nil
}

// 获取区块信息
func (c *Client) getBlock(hash string) (*Block, error) {
	path := "getblock"
	request := []interface{}{
		hash,
	}
	resp, err := c.Call(path, request)

	if err != nil {
		return nil, err
	}
	return NewBlock(resp), nil
}

func (c *Client) getBlockByHeight(height uint64) (*Block, error) {
	path := "getblock"
	request := []interface{}{
		height,
	}
	resp, err := c.Call(path, request)

	if err != nil {
		return nil, err
	}
	return NewBlock(resp), nil
}

func (c *Client) getTransaction(txid string) (*Transaction, error) {
	path := "gettxdetail"

	request := []interface{}{
		txid,
	}
	resp, err := c.Call(path, request)

	if err != nil {
		return nil, err
	}
	return NewTransaction(resp), nil
}

func (c *Client) sendTransaction(rawTx string) (string, error) {
	path := "submittxraw"

	request := []interface{}{
		rawTx,
	}

	resp, err := c.Call(path, request)

	if err != nil {
		return "", err
	}

	return resp.Get("txid").String(), nil
}

func (c *Client) getContractAccountBalence(regid, address string) (*AddrBalance, error) {
	if !isRegIdStr(regid) {
		path := "getaccountinfo"

		request := []interface{}{
			address,
		}

		resp, err := c.Call(path, request)
		if err != nil {
			return nil, err
		}

		if resp.Raw == "{}" || resp.Get("regid").String() == "" {
			return &AddrBalance{
				Address:address,
				Balance:big.NewInt(resp.Get("tokens").Get("WICC").Get("free_amount").Int()),
				TokenBalance:big.NewInt(resp.Get("tokens").Get(regid).Get("free_amount").Int()),
				Registered:false,
				UserID:"",
			}, nil
		}
		return &AddrBalance{
			Address:address,
			Balance:big.NewInt(resp.Get("tokens").Get("WICC").Get("free_amount").Int()),
			TokenBalance: big.NewInt(resp.Get("tokens").Get(regid).Get("free_amount").Int()),
			Registered:true,
			UserID:resp.Get("regid").String(),
		}, nil
	}
	path := "getcontractaccountinfo"

	request := []interface{}{
		regid,
		address,
	}

	resp1, err := c.Call(path, request)
	if err != nil {
		return nil, err
	}

	path = "getaccountinfo"

	request = []interface{}{
		address,
	}

	resp2, err := c.Call(path, request)
	if err != nil {
		return nil, err
	}

	if resp2.Raw == "{}" || resp2.Get("regid").String() == "" {
		return &AddrBalance{
			Address:      address,
			Balance:      big.NewInt(resp2.Get("tokens").Get("WICC").Get("free_amount").Int()),
			TokenBalance: big.NewInt(resp1.Get("free_value").Int()),
			Registered:   false,
			UserID:       "",
		}, nil
	}

	return &AddrBalance{
		Address:      address,
		Balance:      big.NewInt(resp2.Get("tokens").Get("WICC").Get("free_amount").Int()),
		TokenBalance: big.NewInt(resp1.Get("free_value").Int()),
		Registered:   true,
		UserID:       resp2.Get("regid").String(),
	}, nil
}
