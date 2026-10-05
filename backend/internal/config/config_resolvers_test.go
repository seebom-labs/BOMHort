package config

import "testing"

// Every registry resolver is on by default and can be switched off on its own;
// Helm and Compose inject these variables, so a typo here silently changes
// which licenses get resolved.
func TestLoad_ResolverSwitches(t *testing.T) {
	t.Setenv("S3_BUCKETS", "")
	t.Setenv("S3_BUCKET", "")

	switches := map[string]func(*Config) bool{
		"SKIP_GITHUB_RESOLVE":    func(c *Config) bool { return c.SkipGitHubResolve },
		"SKIP_NPM_RESOLVE":       func(c *Config) bool { return c.SkipNPMResolve },
		"SKIP_NUGET_RESOLVE":     func(c *Config) bool { return c.SkipNuGetResolve },
		"SKIP_DEPSDEV_RESOLVE":   func(c *Config) bool { return c.SkipDepsDevResolve },
		"SKIP_PACKAGIST_RESOLVE": func(c *Config) bool { return c.SkipPackagistResolve },
		"SKIP_PYPI_RESOLVE":      func(c *Config) bool { return c.SkipPyPIResolve },
	}
	for env := range switches {
		t.Setenv(env, "")
	}

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for env, get := range switches {
		if get(cfg) {
			t.Errorf("%s unset: resolver should be enabled by default", env)
		}
	}

	for env, get := range switches {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "true")
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if !get(cfg) {
				t.Errorf("%s=true did not disable the resolver", env)
			}
			for other, getOther := range switches {
				if other != env && getOther(cfg) {
					t.Errorf("%s=true also disabled %s", env, other)
				}
			}
		})
	}
}
