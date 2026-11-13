package clickhouse

import (
	"math"
	"testing"
)

func TestImagePageOffset(t *testing.T) {
	for _, tt := range []struct {
		page, size uint64
		want       uint64
		ok         bool
	}{
		{page: 1, size: 50, want: 0, ok: true},
		{page: 3, size: 10, want: 20, ok: true},
		{page: 2, size: 0, want: 0, ok: true},
		{page: 0, size: 10, ok: false},
		{page: math.MaxUint64, size: 2, ok: false},
	} {
		got, ok := imagePageOffset(tt.page, tt.size)
		if got != tt.want || ok != tt.ok {
			t.Errorf("imagePageOffset(%d, %d) = (%d, %t), want (%d, %t)", tt.page, tt.size, got, ok, tt.want, tt.ok)
		}
	}
}
