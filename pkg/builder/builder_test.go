package builder_test

import (
	"testing"

	"github.com/btc-go/bip353/pkg/builder"
)

func TestURIBuilder(t *testing.T) {
	tests := []struct {
		name    string
		build   func() (string, error)
		want    string
		wantErr bool
	}{
		{
			name:  "on-chain only",
			build: func() (string, error) { return builder.NewURIBuilder("bc1qexample").Build() },
			want:  "bitcoin:bc1qexample",
		},
		{
			name:  "bolt12 only",
			build: func() (string, error) { return builder.NewURIBuilder("").WithBOLT12Offer("lno1example").Build() },
			want:  "bitcoin:?lno=lno1example",
		},
		{
			name: "full",
			build: func() (string, error) {
				return builder.NewURIBuilder("bc1qaddr").
					WithBOLT12Offer("lno1offer").
					WithBOLT11Invoice("lnbc1inv").
					WithSilentPayment("sp1addr").
					Build()
			},
			want: "bitcoin:bc1qaddr?lno=lno1offer&lightning=lnbc1inv&sp=sp1addr",
		},
		{
			name:    "empty errors",
			build:   func() (string, error) { return builder.NewURIBuilder("").Build() },
			wantErr: true,
		},
		{
			name: "bolt12 not percent-encoded",
			build: func() (string, error) {
				return builder.NewURIBuilder("").WithBOLT12Offer("lno1qcpjkuepq+abc+xyz").Build()
			},
			want: "bitcoin:?lno=lno1qcpjkuepq+abc+xyz",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.build()
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestMustBuildPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for empty builder")
		}
	}()
	builder.NewURIBuilder("").MustBuild()
}

func TestSetParamIdempotent(t *testing.T) {
	uri, err := builder.NewURIBuilder("").
		WithBOLT12Offer("lno1first").
		WithBOLT12Offer("lno1second").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if uri != "bitcoin:?lno=lno1second" {
		t.Errorf("got %q, want bitcoin:?lno=lno1second", uri)
	}
}