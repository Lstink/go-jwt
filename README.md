## go-jwt 

原本是 `php` 项目中的一个 `jwt` 生成和解析的方法， 后来其中有部分依赖 `go` 项目，为了项目之间身份认证互通，于采用最简单的方式写了一个 `go` 版本的。

### 安装

```bash
go get -u github.com/lstink/go-jwt
```

### 使用

```go
package main

import (
	"context"
	"fmt"
	"github.com/lstink/go-jwt/src/cache"
	"github.com/lstink/go-jwt/src/jerror"
	"github.com/redis/go-redis/v9"
	"time"

	"github.com/lstink/go-jwt"
)

func main() {

	// 用户ID
	uid := 1234
	// 失效时间 一周
	expire := time.Now().Add(time.Hour * 24 * 7).Unix()
	// 生成 token，配置载荷数据
	payload := &jwt.Payload{
		Exp: expire,
		UserInfo: &jwt.UserInfo{
			Id:   uid,
			Time: time.Now().Unix(),
		},
	}
	// 签名的key
	key := "gf1s364g5f1s3gha1ghrt8eh1dsf5s2"
	// 这里使用redis做缓存
	redisOption := &redis.Options{
		Addr:     "127.0.0.1:6379",
		Password: "",
		DB:       6,
	}
	// 初始化 jwt 实例
	jwtServer := jwt.NewJwt(key, cache.NewRedisCache(context.Background(), redisOption))
	// 生成 token
	token, err := jwtServer.Encode(payload)
	if err != nil {
		panic(err)
	}
	fmt.Println("生成的token", token)
	// 续签 token，续签后原来的token将会加入黑名单中，黑名单目前有效时间为1天
	refreshToken, err := jwtServer.RefreshToken(token, time.Hour) // 这里传入续签的token 和 续签时间, 这里还可以传入第三个参数【黑名单有效时间，默认为1天】
	if err != nil {
		return
	}
	fmt.Println("续签的token", refreshToken)

	// 解析新token
	if payload, err = jwtServer.Decode(refreshToken); err != nil {
		return
	}

	// 解析token
	res, err := jwtServer.Decode(refreshToken)
	if err != nil {
		fmt.Println("出现错误")
		if e, ok := err.(jerror.IError); ok {
			fmt.Println(e.Code())
			panic(err)
		}
	}

	fmt.Printf("解析结果 {Exp: %v, UserInfo: {Id: %v, Time: %v}}", res.Exp, res.UserInfo.Id, res.UserInfo.Time)

}



```