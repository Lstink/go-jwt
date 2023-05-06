package main

import (
	"fmt"
	"github.com/lstink/go-jwt"
	"time"
)

func main() {

	// 用户ID
	uid := 1234
	// 失效时间 一周后
	expire := time.Now().Add(time.Hour * 24 * 7).Unix()
	// 生成 token
	payload := &jwt.Payload{
		Exp: expire,
		UserInfo: &jwt.UserInfo{
			Id:   uid,
			Time: time.Now().Unix(),
		},
	}

	// 签名的key
	key := "gf1s364g5f1s3gha1ghrt8eh1dsf5s2"

	token, err := jwt.NewJwt().Encode(payload, key)

	if err != nil {
		panic(err)
	}

	fmt.Println("生成的token", token)

	// 解析token
	res, err := jwt.NewJwt().Decode(token, key)
	if err != nil {
		panic(err)
	}

	fmt.Printf("解析结果 {Exp: %v, UserInfo: {Id: %v, Time: %v}}", res.Exp, res.UserInfo.Id, res.UserInfo.Time)

}
