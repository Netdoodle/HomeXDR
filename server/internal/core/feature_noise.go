package core

import (
	"context"
	"time"

	"github.com/Netdoodle/homexdr/server/internal/notify"
)

// initNoise sets up suppressions and notifications.
func (c *Core) initNoise(ctx context.Context) {
	c.Suppress = NewSuppressor(c.State, c.Log)
	c.Notify = notify.New(c.State, c.Log)
	c.Notify.AddDigestSection("Data health", func(ctx context.Context, _ time.Time) ([]string, error) {
		_, lines := c.FeedHealthDigest(ctx)
		return lines, nil
	})
}

// runNoise is the background loop of suppressions and notifications.
func (c *Core) runNoise(ctx context.Context) {
	c.Notify.Run(ctx)
}
