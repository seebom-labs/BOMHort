package privatevuln

import "github.com/seebom-labs/bomhort/backend/internal/rulesource"

// Watcher keeps the private vulnerability advisories current.
type Watcher = rulesource.Watcher[*Index]

// Watch returns a watcher for the private vulnerabilities document described by
// opts. Nothing is fetched until the first Refresh.
func Watch(opts rulesource.Options) (*Watcher, error) {
	f, err := rulesource.New(opts)
	if err != nil {
		return nil, err
	}
	return rulesource.NewWatcher(f, func(data []byte) (*Index, error) {
		return Parse(data, f.Describe())
	}), nil
}
