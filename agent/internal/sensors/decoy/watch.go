package decoy

// watchKind is a real-time notification about a decoy (Linux inotify).
type watchKind int

const (
	watchAccess watchKind = iota // opened or read
	watchModify                  // content written
	watchAttrib                  // permissions, owner, times or link count changed
	watchDelete                  // the file was deleted
	watchMove                    // the file was renamed or moved
)

// watcher delivers real-time notifications for individual decoy files. remove must be
// called before the agent itself touches a decoy, so its own reads and writes are never
// seen; add again afterwards.
type watcher interface {
	add(path string) error
	remove(path string)
	close()
}
