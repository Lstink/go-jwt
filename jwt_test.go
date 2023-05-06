package jwt

import (
	"reflect"
	"testing"
)

func TestJwt_Decode(t1 *testing.T) {
	type args struct {
		jwt string
		key string
	}
	var tests []struct {
		name        string
		args        args
		wantPayload *Payload
		wantErr     bool
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &Jwt{}
			gotPayload, err := t.Decode(tt.args.jwt, tt.args.key)
			if (err != nil) != tt.wantErr {
				t1.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPayload, tt.wantPayload) {
				t1.Errorf("Decode() gotPayload = %v, want %v", gotPayload, tt.wantPayload)
			}
		})
	}
}

func TestJwt_urlSafeB64Decode(t1 *testing.T) {
	type args struct {
		input string
	}
	var tests []struct {
		name    string
		args    args
		wantRes []byte
		wantErr bool
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &Jwt{}
			gotRes, err := t.urlSafeB64Decode(tt.args.input)
			if (err != nil) != tt.wantErr {
				t1.Errorf("urlSafeB64Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRes, tt.wantRes) {
				t1.Errorf("urlSafeB64Decode() gotRes = %v, want %v", gotRes, tt.wantRes)
			}
		})
	}
}

func TestJwt_verify(t1 *testing.T) {
	type args struct {
		msg  string
		sign []byte
		key  string
	}
	var tests []struct {
		name string
		args args
		want bool
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &Jwt{}
			if got := t.verify(tt.args.msg, tt.args.sign, tt.args.key); got != tt.want {
				t1.Errorf("verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewJwt(t *testing.T) {
	var tests []struct {
		name string
		want *Jwt
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewJwt(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewJwt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJwt_Encode(t1 *testing.T) {
	type args struct {
		payload *Payload
		key     string
	}
	var tests []struct {
		name      string
		args      args
		wantToken string
		wantErr   bool
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &Jwt{}
			gotToken, err := t.Encode(tt.args.payload, tt.args.key)
			if (err != nil) != tt.wantErr {
				t1.Errorf("Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotToken != tt.wantToken {
				t1.Errorf("Encode() gotToken = %v, want %v", gotToken, tt.wantToken)
			}
		})
	}
}

func TestJwt_sign(t1 *testing.T) {
	type args struct {
		input []byte
		key   []byte
	}
	var tests []struct {
		name string
		args args
		want []byte
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &Jwt{}
			if got := t.sign(tt.args.input, tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t1.Errorf("sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJwt_urlSafeB64Encode(t1 *testing.T) {
	type args struct {
		input []byte
	}
	var tests []struct {
		name string
		args args
		want string
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &Jwt{}
			if got := t.urlSafeB64Encode(tt.args.input); got != tt.want {
				t1.Errorf("urlSafeB64Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}
