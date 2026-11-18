package main

import (
	"net/url"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/extrafields"
)

func TestParseExtraFieldFilter(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		want    clickhouse.ExtraFieldFilter
		wantErr bool
	}{
		{name: "none", query: ""},
		{name: "name only", query: "extra_field=owner_contact", want: clickhouse.ExtraFieldFilter{Name: "owner_contact"}},
		{name: "name and value", query: "extra_field=owner_contact&extra_value=team%40example.com",
			want: clickhouse.ExtraFieldFilter{Name: "owner_contact", Value: "team@example.com"}},
		{name: "value is trimmed", query: "extra_field=owner_contact&extra_value=%20x%20",
			want: clickhouse.ExtraFieldFilter{Name: "owner_contact", Value: "x"}},
		{name: "value without name", query: "extra_value=x", wantErr: true},
		{name: "bad name", query: "extra_field=Owner%20Contact", wantErr: true},
		{name: "injection-shaped name", query: "extra_field=a'%5D%20OR%201%3D1", wantErr: true},
		{name: "over-long value", query: "extra_field=a&extra_value=" + strings.Repeat("x", extrafields.MaxValueLen+1), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			got, msg := parseExtraFieldFilter(q)
			if (msg != "") != tc.wantErr {
				t.Fatalf("msg = %q, wantErr %v", msg, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("filter = %+v, want %+v", got, tc.want)
			}
		})
	}
}
