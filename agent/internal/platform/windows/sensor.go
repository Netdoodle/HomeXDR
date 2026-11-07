//go:build windows

package windows

import (
	"container/list"
	"sync"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"github.com/Netdoodle/homexdr/shared/api"
	"github.com/Netdoodle/homexdr/shared/event"
)

// sensorState is the shared status bookkeeping of the Windows sensors, the same pattern
// as the Linux sensors use.
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
