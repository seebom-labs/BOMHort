package claimlock

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	leaseName = "bomhort-ingestion-queue-claims"
	// Kubernetes' defaults: a dead holder blocks claims for at most 15s.
	leaseDuration = 15 * time.Second
	renewDeadline = 10 * time.Second
	retryPeriod   = 2 * time.Second
)

var (
	// maxHold bounds one critical section. client-go releases a Lease whose
	// renewal failed no earlier than renewDeadline after it started, and
	// other holders wait leaseDuration, so a result that is ready before
	// maxHold (measured from before acquisition) was written while we held it.
	maxHold = renewDeadline / 2
)

// ErrLeaseLost reports a critical section that may have overlapped another
// holder; its result must be discarded.
const keyedLockShards = 64

var ErrLeaseLost = errors.New("claim lock lost or held too long; result discarded")

type Locker interface {
	WithLock(context.Context, func(context.Context) error) error
}

type KeyedLocker interface {
	WithKey(context.Context, string, func(context.Context) error) error
}

type localLocker struct {
	gate chan struct{}
}

type shardedLocker struct {
	mu        sync.Mutex
	locks     map[uint32]Locker
	workerID  string
	prefix    string
	maxHold   time.Duration
	client    kubernetes.Interface
	namespace string
}

// Local serialises callers inside one process only. Separate worker
// processes (Docker Compose replicas) are not serialised by it.
func Local() Locker {
	return &localLocker{gate: make(chan struct{}, 1)}
}

func (l *localLocker) WithLock(ctx context.Context, fn func(context.Context) error) error {
	select {
	case l.gate <- struct{}{}:
		defer func() { <-l.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	return fn(ctx)
}

type kubernetesLocker struct {
	local                        Locker
	lock                         resourcelock.Interface
	name                         string
	leaseDuration, renewDeadline time.Duration
	retryPeriod, maxHold         time.Duration
}

func New(workerID string) (Locker, error) {
	return NewNamed(workerID, leaseName)
}

func NewNamed(workerID, name string) (Locker, error) {
	return NewNamedWithMaxHold(workerID, name, maxHold)
}

func NewNamedWithMaxHold(workerID, name string, maxHold time.Duration) (Locker, error) {
	if name == "" {
		return nil, errors.New("lease name is required")
	}
	if maxHold <= 0 {
		return nil, errors.New("claim lock max hold must be positive")
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
			return Local(), nil
		}
		return nil, errors.New("POD_NAMESPACE is required for the Kubernetes claim lock")
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config for claim lock: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client for claim lock: %w", err)
	}
	return newKubernetesLocker(workerID, namespace, name, maxHold, client)
}

// NewShardedNamed creates a bounded set of named Leases. Equal keys always
// share a Lease; different keys may share one of 64 Leases and serialize.
func NewShardedNamed(workerID, prefix string, maxHold time.Duration) (KeyedLocker, error) {
	if prefix == "" || len(prefix)+3 > 63 {
		return nil, errors.New("lease name prefix must fit a 63-character Kubernetes name")
	}
	if maxHold <= 0 {
		return nil, errors.New("claim lock max hold must be positive")
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
			return nil, errors.New("POD_NAMESPACE is required for the Kubernetes claim lock")
		}
		return &shardedLocker{locks: make(map[uint32]Locker), workerID: workerID, prefix: prefix, maxHold: maxHold}, nil
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config for claim lock: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client for claim lock: %w", err)
	}
	return &shardedLocker{
		locks: make(map[uint32]Locker), workerID: workerID, prefix: prefix,
		maxHold: maxHold, client: client, namespace: namespace,
	}, nil
}

func LocalKeyed() KeyedLocker {
	return &shardedLocker{locks: make(map[uint32]Locker), maxHold: maxHold}
}

func (l *shardedLocker) WithKey(ctx context.Context, key string, fn func(context.Context) error) error {
	shard := keyShard(key)
	locker, err := l.locker(shard)
	if err != nil {
		return err
	}
	return locker.WithLock(ctx, fn)
}

func keyShard(key string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(key))
	return hash.Sum32() % keyedLockShards
}

func (l *shardedLocker) locker(shard uint32) (Locker, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if locker := l.locks[shard]; locker != nil {
		return locker, nil
	}
	if l.client == nil {
		locker := Local()
		l.locks[shard] = locker
		return locker, nil
	}
	name := fmt.Sprintf("%s-%02x", l.prefix, shard)
	locker, err := newKubernetesLocker(l.workerID, l.namespace, name, l.maxHold, l.client)
	if err != nil {
		return nil, err
	}
	l.locks[shard] = locker
	return locker, nil
}

func newKubernetesLocker(workerID, namespace, name string, maxHold time.Duration, client kubernetes.Interface) (Locker, error) {
	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		namespace,
		name,
		client.CoreV1(),
		client.CoordinationV1(),
		resourcelock.ResourceLockConfig{Identity: workerID + "/" + uuid.NewString()},
	)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes Lease lock: %w", err)
	}
	return &kubernetesLocker{
		local: Local(), lock: lock, name: name,
		leaseDuration: 3 * maxHold, renewDeadline: 2 * maxHold,
		retryPeriod: 2 * maxHold / 5, maxHold: maxHold,
	}, nil
}

func (l *kubernetesLocker) WithLock(ctx context.Context, fn func(context.Context) error) error {
	return l.local.WithLock(ctx, func(ctx context.Context) error {
		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// shortcut: monotonic time stops during host suspend, so a suspended
		// (not merely paused) node can overrun maxHold unnoticed; acceptable for pods.
		start := time.Now()
		started := make(chan struct{})
		result := make(chan error, 1)
		runDone := make(chan struct{})
		elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:            l.lock,
			LeaseDuration:   l.leaseDuration,
			RenewDeadline:   l.renewDeadline,
			RetryPeriod:     l.retryPeriod,
			ReleaseOnCancel: true,
			Name:            l.name,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(leaderCtx context.Context) {
					close(started)
					fnCtx, cancelFn := context.WithDeadline(leaderCtx, start.Add(l.maxHold))
					stopCancel := context.AfterFunc(ctx, cancelFn)
					err := fn(fnCtx)
					if leaderCtx.Err() != nil || time.Since(start) >= l.maxHold {
						err = ErrLeaseLost
					}
					result <- err
					stopCancel()
					cancelFn()
					cancel()
				},
				OnStoppedLeading: func() {},
			},
		})
		if err != nil {
			return fmt.Errorf("configure Kubernetes claim lock: %w", err)
		}
		go func() {
			elector.Run(runCtx)
			close(runDone)
		}()
		select {
		case err := <-result:
			<-runDone
			return err
		case <-ctx.Done():
			select {
			case <-started:
				err := <-result
				<-runDone
				if err != nil {
					return err
				}
				return ctx.Err()
			default:
				cancel()
				<-runDone
				return ctx.Err()
			}
		case <-runDone:
			select {
			case err := <-result:
				return err
			case <-started:
				return <-result
			default:
				return errors.New("Kubernetes claim lock stopped before acquiring the lease")
			}
		}
	})
}

// RunLeader runs fn only on the single worker replica that holds leaseName.
// In-cluster, it competes for the Kubernetes Lease using client-go leader election.
// Outside Kubernetes (e.g. local Docker or unit tests), it runs fn in this process directly.
// If leadership is lost, the context passed to fn is cancelled and another replica takes over.
func RunLeader(ctx context.Context, workerID, leaseName string, fn func(leaderCtx context.Context)) error {
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
			go fn(ctx)
			return nil
		}
		return errors.New("POD_NAMESPACE is required for Kubernetes leader election")
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("load in-cluster config for leader election: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("create Kubernetes client for leader election: %w", err)
	}
	return runLeaderWithClient(ctx, client, namespace, leaseName, workerID, fn)
}

func runLeaderWithClient(ctx context.Context, client kubernetes.Interface, namespace, leaseName, workerID string, fn func(leaderCtx context.Context)) error {
	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		namespace,
		leaseName,
		client.CoreV1(),
		client.CoordinationV1(),
		resourcelock.ResourceLockConfig{Identity: workerID + "/" + uuid.NewString()},
	)
	if err != nil {
		return fmt.Errorf("create Kubernetes Lease lock: %w", err)
	}

	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   leaseDuration,
		RenewDeadline:   renewDeadline,
		RetryPeriod:     retryPeriod,
		ReleaseOnCancel: true,
		Name:            leaseName,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leaderCtx context.Context) {
				log.Printf("Leader lease %q acquired by %s (sync owner)", leaseName, workerID)
				fn(leaderCtx)
			},
			OnStoppedLeading: func() {
				log.Printf("Leader lease %q released by %s", leaseName, workerID)
			},
		},
	})
	if err != nil {
		return fmt.Errorf("configure Kubernetes leader election: %w", err)
	}

	go elector.Run(ctx)
	return nil
}
