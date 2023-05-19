package jerror

var (
	EncodeException = New("encode exception", 1001)
	DecodeException = New("decode exception", 1002)
	ExpireException = New("token expire", 2001)
	RedisException  = New("redis exception", 2002)
)
