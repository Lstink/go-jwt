package jerror

type JError struct {
	s    string
	code int
}

func (e *JError) Error() string {
	return e.s
}

func (e *JError) Code() int {
	return e.code
}

func New(msg string, code int) *JError {
	return &JError{
		s:    msg,
		code: code,
	}
}
