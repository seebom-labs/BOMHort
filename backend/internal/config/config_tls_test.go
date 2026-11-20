package config

import "testing"

func setTLSDefaults(t *testing.T) {
	t.Helper()
	t.Setenv("CLICKHOUSE_SECURE", "false")
	t.Setenv("CLICKHOUSE_SKIP_VERIFY", "false")
	t.Setenv("CLICKHOUSE_CA_FILE", "")
	t.Setenv("CLICKHOUSE_CERT_FILE", "")
	t.Setenv("CLICKHOUSE_KEY_FILE", "")
}

func TestLoad_ClickHouseTLSBooleans(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{value: "true", want: true},
		{value: "TRUE", want: true},
		{value: "True", want: true},
		{value: "1", want: true},
		{value: "false", want: false},
		{value: "FALSE", want: false},
		{value: "0", want: false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			setTLSDefaults(t)
			t.Setenv("CLICKHOUSE_SECURE", tc.value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if cfg.ClickHouseSecure != tc.want {
				t.Errorf("ClickHouseSecure = %t, want %t", cfg.ClickHouseSecure, tc.want)
			}
		})
	}
}

func TestLoad_ClickHouseTLSRejectsInvalidBooleans(t *testing.T) {
	for _, key := range []string{"CLICKHOUSE_SECURE", "CLICKHOUSE_SKIP_VERIFY"} {
		for _, value := range []string{"TRUEE", "yes please", ""} {
			t.Run(key+"/"+value, func(t *testing.T) {
				setTLSDefaults(t)
				t.Setenv(key, value)
				if _, err := Load(); err == nil {
					t.Fatalf("Load() accepted %s=%q", key, value)
				}
			})
		}
	}
}

func TestLoad_ClickHouseTLSRejectsInconsistentOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*testing.T)
	}{
		{name: "skip verify without TLS", set: func(t *testing.T) { t.Setenv("CLICKHOUSE_SKIP_VERIFY", "true") }},
		{name: "CA without TLS", set: func(t *testing.T) { t.Setenv("CLICKHOUSE_CA_FILE", "/ca.crt") }},
		{name: "client cert without TLS", set: func(t *testing.T) { t.Setenv("CLICKHOUSE_CERT_FILE", "/client.crt") }},
		{name: "client key without TLS", set: func(t *testing.T) { t.Setenv("CLICKHOUSE_KEY_FILE", "/client.key") }},
		{name: "missing client key", set: func(t *testing.T) {
			t.Setenv("CLICKHOUSE_SECURE", "true")
			t.Setenv("CLICKHOUSE_CERT_FILE", "/client.crt")
		}},
		{name: "missing client cert", set: func(t *testing.T) {
			t.Setenv("CLICKHOUSE_SECURE", "true")
			t.Setenv("CLICKHOUSE_KEY_FILE", "/client.key")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setTLSDefaults(t)
			tc.set(t)
			if _, err := Load(); err == nil {
				t.Fatal("Load() accepted inconsistent ClickHouse TLS settings")
			}
		})
	}
}
