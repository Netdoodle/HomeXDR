package darwin

import (
	"container/list"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// The files without a darwin build tag hold the parsers and event mapping, so their
// tests run on every OS; the darwin-tagged files do the system calls and run commands.

// errUnavailable marks an implementation that cannot run here (no eslogger, no Full Disk
// Access, too old a macOS); the sensor then tries the next one.
type errUnavailable struct{ err error }

func (e errUnavailable) Error() string { return e.err.Error() }
func (e errUnavailable) Unwrap() error { return e.err }

func unavailable(err error) error { return errUnavailable{err} }

func isUnavailable(err error) bool {
	var u errUnavailable
	return errors.As(err, &u)
}

// sensorState is the shared status bookkeeping of the macOS sensors.
type sensorState struct {
	mu     sync.Mutex
	name   string
	impl   string
	state  string
	errMsg string
	events uint64
}

func (s *sensorState) set(impl, state, msg string) {
	s.mu.Lock()
	s.impl, s.state, s.errMsg = impl, state, msg
	s.mu.Unlock()
}

func (s *sensorState) count() {
	s.mu.Lock()
	s.events++
	s.mu.Unlock()
}

// Name returns the sensor kind.
func (s *sensorState) Name() string { return s.name }

// Status reports health.
func (s *sensorState) Status() api.SensorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state
	if st == "" {
		st = api.SensorRunning
	}
	return api.SensorStatus{Name: s.name, Impl: s.impl, State: st, Error: s.errMsg, Events: s.events}
}

// countingEmitter counts events into the sensor's status.
type countingEmitter struct {
	s   *sensorState
	out platform.Emitter
}

func (c countingEmitter) Emit(e *event.Event) {
	c.s.count()
	c.out.Emit(e)
}

// lru is a small fixed-size LRU map.
type lru[K comparable, V any] struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[K]*list.Element
}

type lruEntry[K comparable, V any] struct {
	k K
	v V
}

func newLRU[K comparable, V any](max int) *lru[K, V] {
	return &lru[K, V]{max: max, ll: list.New(), m: map[K]*list.Element{}}
}

func (c *lru[K, V]) get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*lruEntry[K, V]).v, true
	}
	var zero V
	return zero, false
}

func (c *lru[K, V]) put(k K, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		el.Value.(*lruEntry[K, V]).v = v
		c.ll.MoveToFront(el)
		return
	}
	c.m[k] = c.ll.PushFront(&lruEntry[K, V]{k, v})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*lruEntry[K, V]).k)
	}
}

func (c *lru[K, V]) remove(k K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		c.ll.Remove(el)
		delete(c.m, k)
	}
}

// procSummary is what we remember about recently seen processes, to describe parents
// and exits.
type procSummary struct {
	Name, Executable, CommandLine string
}

// joinArgs renders argv as one command line, quoting arguments that need it.
func joinArgs(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if a == "" || strings.ContainsAny(a, " \t\"'\\$`") {
			b.WriteByte('"')
			b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(a))
			b.WriteByte('"')
			continue
		}
		b.WriteString(a)
	}
	return b.String()
}

// decodeExit splits a wait status into an exit code and signal. A process killed by
// signal N gets exit code 128+N, like a shell reports it.
func decodeExit(status uint32) (code int64, signal int) {
	if sig := status & 0x7f; sig != 0 {
		return 128 + int64(sig), int(sig)
	}
	return int64((status >> 8) & 0xff), 0
}

// startTimeFromMicros turns a start key (microseconds since the Unix epoch) into a time.
func startTimeFromMicros(us uint64) time.Time {
	if us == 0 {
		return time.Time{}
	}
	return time.UnixMicro(int64(us)).UTC()
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func itoa(u uint32) string { return strconv.FormatUint(uint64(u), 10) }
