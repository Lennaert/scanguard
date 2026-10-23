package scanguard

import "time"

const (
	// sweepEvery is how often the memory stores scan for expired entries.
	sweepEvery = time.Minute
	// evictSample is how many entries are looked at to pick one to evict
	// when a store is full. Go starts map iteration at a random spot, so
	// this is a cheap random sample, like Redis' approximate LRU.
	evictSample = 8
)

// expiringSet maps keys to expiry times. It is not safe for concurrent
// use; callers hold their own lock.
type expiringSet struct {
	m         map[string]time.Time
	lastSweep time.Time
}

// set stores key until the given time. When max > 0 and a new key would
// exceed it, the entry expiring soonest within a random sample is evicted.
func (s *expiringSet) set(key string, until, now time.Time, max int) {
	if s.m == nil {
		s.m = make(map[string]time.Time)
	}
	if _, ok := s.m[key]; !ok {
		s.sweep(now)
		if max > 0 && len(s.m) >= max {
			s.evict()
		}
	}
	s.m[key] = until
}

func (s *expiringSet) active(key string, now time.Time) bool {
	until, ok := s.m[key]
	return ok && now.Before(until)
}

func (s *expiringSet) delete(key string) { delete(s.m, key) }

func (s *expiringSet) sweep(now time.Time) {
	if now.Sub(s.lastSweep) < sweepEvery {
		return
	}
	for k, until := range s.m {
		if !now.Before(until) {
			delete(s.m, k)
		}
	}
	s.lastSweep = now
}

func (s *expiringSet) evict() {
	var victim string
	var soonest time.Time
	n := 0
	for k, until := range s.m {
		if n == 0 || until.Before(soonest) {
			victim, soonest = k, until
		}
		if n++; n == evictSample {
			break
		}
	}
	delete(s.m, victim)
}
