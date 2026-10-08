package main

import (
	"fmt"
	"time"
)

// deferError tells the job loop that a job must run again later rather than
// be marked failed: nothing about the SBOM is wrong, an upstream the pipeline
// depends on (GitHub) is temporarily unavailable. until is when it is worth
// trying again; cause is what happened.
type deferError struct {
	until time.Time
	cause error
}

func (e *deferError) Error() string {
	return fmt.Sprintf("deferred until %s: %v", e.until.Format(time.RFC3339), e.cause)
}

func (e *deferError) Unwrap() error { return e.cause }
