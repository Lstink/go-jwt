package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lstink/go-jwt/src/cache"
	"github.com/lstink/go-jwt/src/utils"
	"strconv"
	"strings"
	"time"

	"github.com/lstink/go-jwt/src/jerror"
)

type UserInfo struct {
	Id   int64
	Time int64
}
type Payload struct {
	Exp      int64
	UserInfo *UserInfo
}

type Jwt struct {
	key   string
	cache cache.ICache
}

const blockPrefix = "goJwt:"
const alg = "HS256"

// 黑名单有效时长
var cacheExpire = time.Hour * 24

func NewJwt(key string, cache cache.ICache) *Jwt {
	return &Jwt{key: key, cache: cache}
}

// 获取缓存的key
func (t *Jwt) getCacheKey(jwt string) string {
	return fmt.Sprintf(blockPrefix+"%s:%s", utils.Md5(t.key), utils.Md5(jwt))
}

// RefreshToken 续签token
func (t *Jwt) RefreshToken(jwt string, d time.Duration, blockD ...time.Duration) (token string, err error) {
	// 解析 token
	var payload *Payload
	if payload, err = t.Decode(jwt); err != nil {
		return
	}
	// 获取 key
	cacheKey := t.getCacheKey(jwt)

	// 判断这个 token 是不是在黑名单里面
	if t.cache.Has(cacheKey) {
		err = jerror.ExpireException
		return
	}

	now := time.Now()
	payload.UserInfo.Time = now.Unix()
	payload.Exp = now.Add(d).Unix()
	// 重新生成 token
	if token, err = t.Encode(payload); err != nil {
		return
	}
	// 原来的token加入黑名单
	if len(blockD) > 0 {
		cacheExpire = blockD[0]
	}
	if err = t.cache.Set(cacheKey, strconv.FormatInt(now.Unix(), 10), cacheExpire); err != nil {
		err = jerror.RedisException
		return
	}

	return
}

// Encode generate token
func (t *Jwt) Encode(payload *Payload) (token string, err error) {
	header := map[string]string{
		"typ": "JWT",
		"alg": alg,
	}
	var (
		headerByte  []byte
		payloadByte []byte
		segments    []string
	)

	if headerByte, err = json.Marshal(header); err != nil {
		err = jerror.EncodeException
		return
	}

	if payloadByte, err = json.Marshal(payload); err != nil {
		err = jerror.EncodeException
		return
	}

	segments = append(segments, t.urlSafeB64Encode(headerByte))
	segments = append(segments, t.urlSafeB64Encode(payloadByte))
	signingInput := strings.Join(segments, ".")
	signature := t.sign([]byte(signingInput), []byte(t.key))
	segments = append(segments, t.urlSafeB64Encode(signature))
	token = strings.Join(segments, ".")
	return
}

func (t *Jwt) urlSafeB64Encode(input []byte) string {
	return base64.URLEncoding.EncodeToString(input)
}

// 签名
func (t *Jwt) sign(input []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(input)
	return h.Sum(nil)
}

// Decode decode token
func (t *Jwt) Decode(jwt string) (payload *Payload, err error) {
	// 获取 key
	cacheKey := t.getCacheKey(jwt)

	// 判断这个 token 是不是在黑名单里面
	if t.cache.Has(cacheKey) {
		err = jerror.ExpireException
		return
	}

	timestamp := time.Now().Unix()
	tks := strings.Split(jwt, ".")
	if len(tks) != 3 {
		err = jerror.DecodeException
		return
	}

	head64 := tks[0]
	body64 := tks[1]
	cryptob64 := tks[2]

	var headerByte []byte
	var payloadByte []byte
	var sigByte []byte
	if headerByte, err = t.urlSafeB64Decode(head64); err != nil || headerByte == nil {
		err = jerror.DecodeException
		return
	}
	if payloadByte, err = t.urlSafeB64Decode(body64); err != nil || payloadByte == nil {
		err = jerror.DecodeException
		return
	}

	if sigByte, err = t.urlSafeB64Decode(cryptob64); err != nil || sigByte == nil {
		err = jerror.DecodeException
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
	if header.Alg != alg {
		err = jerror.DecodeException
		return
	}

	// 检查签名
	if !t.verify(head64+"."+body64, sigByte, t.key) {
		err = jerror.DecodeException
		return
	}

	err = json.Unmarshal(payloadByte, &payload)
	if err != nil {
		err = jerror.DecodeException
		return
	}

	if timestamp >= payload.Exp {
		err = jerror.ExpireException
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
