package docstore

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
)

func TestImmutableFSConcurrentWriters(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	ref, err := ImmutableRef(store, "tea/release/1")
	if err != nil {
		t.Fatal(err)
	}
	const writers = 32
	var wg sync.WaitGroup
	type result struct {
		value string
		wrote bool
		err   error
	}
	results := make(chan result, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			value := fmt.Sprintf("value-%d", i)
			wrote, err := PutIfAbsent(context.Background(), store, ref, []byte(value))
			results <- result{value, wrote, err}
		}(i)
	}
	wg.Wait()
	close(results)
	var winner string
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.wrote {
			if winner != "" {
				t.Fatal("more than one writer succeeded")
			}
			winner = r.value
		}
	}
	if winner == "" {
		t.Fatal("no writer succeeded")
	}
	rc, err := store.Get(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil || string(got) != winner {
		t.Fatalf("got %q, err %v, want %q", got, err, winner)
	}
}
