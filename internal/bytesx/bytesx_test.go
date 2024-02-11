// Package bytesx provides functions operating on bytes.
//
// Specifically we implement these operations:
//
// 1. generating random bytes;
//
// 2. OpenVPN options encoding and decoding;
//
// 3. PKCS#7 padding and unpadding.
package bytesx

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_GenRandomBytes(t *testing.T) {
	const smallBuffer = 128
	data, err := GenRandomBytes(smallBuffer)
	if err != nil {
		t.Fatal("unexpected error", err)
	}
	if len(data) != smallBuffer {
		t.Fatal("unexpected returned buffer length")
	}
}

func Test_EncodeOptionStringToBytes(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{{
		name: "common case",
		args: args{
			s: "test",
		},
		want:    []byte{0, 5, 116, 101, 115, 116, 0},
		wantErr: nil,
	}, {
		name: "encoding empty string",
		args: args{
			s: "",
		},
		want:    []byte{0, 1, 0},
		wantErr: nil,
	}, {
		name: "encoding a very large string",
		args: args{
			s: string(make([]byte, 1<<16)),
		},
		want:    nil,
		wantErr: ErrEncodeOption,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeOptionStringToBytes(tt.args.s)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("encodeOptionStringToBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func Test_DecodeOptionStringFromBytes(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr error
	}{{
		name: "with zero-length input",
		args: args{
			b: nil,
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with input length equal to one",
		args: args{
			b: []byte{0x00},
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with input length equal to two",
		args: args{
			b: []byte{0x00, 0x00},
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with length mismatch and length < actual length",
		args: args{
			b: []byte{
				0x00, 0x03, // length = 3
				0x61, 0x61, 0x61, 0x61, 0x61, // aaaaa
				0x00, // trailing zero
			},
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with length mismatch and length > actual length",
		args: args{
			b: []byte{
				0x00, 0x44, // length = 68
				0x61, 0x61, 0x61, 0x61, 0x61, // aaaaa
				0x00, // trailing zero
			},
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with missing trailing \\0",
		args: args{
			b: []byte{
				0x00, 0x05, // length = 5
				0x61, 0x61, 0x61, 0x61, 0x61, // aaaaa
			},
		},
		want:    "",
		wantErr: ErrDecodeOption,
	}, {
		name: "with valid input",
		args: args{
			b: []byte{
				0x00, 0x06, // length = 6
				0x61, 0x61, 0x61, 0x61, 0x61, // aaaaa
				0x00, // trailing zero
			},
		},
		want:    "aaaaa",
		wantErr: nil,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeOptionStringFromBytes(tt.args.b)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("decodeOptionStringFromBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
