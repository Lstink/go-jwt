package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type UserInfo struct {
	Id   int
	Time int64
}
type Payload struct {
	Exp      int64
	UserInfo *UserInfo
}

type Jwt struct {
}

func NewJwt() *Jwt {
	return &Jwt{}
}

func (t *Jwt) Encode() string {
	return "This is Jwt for v0.0.3"
}

func (t *Jwt) Decode(jwt, key string) (payload *Payload, err error) {
	timestamp := time.Now().Unix()
	tks := strings.Split(jwt, ".")
	if len(tks) != 3 {
		err = errors.New("token解析异常")
		return
	}

	head64 := tks[0]
	body64 := tks[1]
	cryptob64 := tks[2]

	var headerByte []byte
	var payloadByte []byte
	var sigByte []byte
	if headerByte, err = t.urlSafeB64Decode(head64); err != nil || headerByte == nil {
		return
	}
	if payloadByte, err = t.urlSafeB64Decode(body64); err != nil || payloadByte == nil {
		return
	}

	if sigByte, err = t.urlSafeB64Decode(cryptob64); err != nil || sigByte == nil {
		return
	}

	type Header struct {
		Typ string
		Alg string
	}

	var (
		header *Header
	)
	err = json.Unmarshal(headerByte, &header)
	if err != nil {
		return
	}
	if header.Alg != "HS256" {
		err = errors.New("token解析异常")
		return
	}

	// 检查签名
	if !t.verify(head64+"."+body64, sigByte, key) {
		err = errors.New("token解析异常")
		return
	}

	err = json.Unmarshal(payloadByte, &payload)
	if err != nil {
		return
	}

	if timestamp >= payload.Exp {
		err = errors.New("登录已过期")
		return
	}

	return
}

// 解码
func (t *Jwt) urlSafeB64Decode(input string) (res []byte, err error) {
	remainder := len(input) % 4
	if remainder > 0 {
		padlen := 4 - remainder
		input += strings.Repeat("=", padlen)
	}

	return base64.URLEncoding.DecodeString(input)
}

// 验证
func (t *Jwt) verify(msg string, sign []byte, key string) bool {

	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(msg))
	return hmac.Equal(sign, m.Sum(nil))
}
