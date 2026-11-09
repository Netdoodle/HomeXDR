package core

import (
	"context"

	"github.com/Netdoodle/homexdr/server/internal/backup"
)

// initBackup sets up cold archives of events in S3-compatible storage (Data retention page).
func (c *Core) initBackup(ctx context.Context) {
	c.Backup = backup.New(backup.Deps{State: c.State, Log: c.Log, Usage: c.usage, Export: c.Events.ExportRaw, Insert: c.Events.Insert})
	if err := c.Backup.Load(ctx); err != nil {
		c.Log.Error("load backup settings", "err", err)
	}
}

func (c *Core) runBackup(ctx context.Context) { c.Backup.Run(ctx) }
