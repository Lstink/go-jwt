package jerror

type IError interface {
	Error() string
	Code() int
}
