package core

import (
	"context"
	"sync"
)

// RunFeatures runs the background loops of the alert, health and network features until
// ctx ends.
func (c *Core) RunFeatures(ctx context.Context) {
	var wg sync.WaitGroup
	for _, run := range []func(context.Context){c.runNoise, c.runHealth, c.runNetwork, c.runAV, c.runBackup} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run(ctx)
		}()
	}
	wg.Wait()
}
