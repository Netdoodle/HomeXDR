//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Netdoodle/homexdr/agent/internal/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "HomeXDRAgent"
	serviceDisplayName = "HomeXDR Agent"
	serviceDescription = "HomeXDR endpoint telemetry and response. Remove with: homexdr-agent uninstall"
	// stopTimeout bounds how long Uninstall waits for the service to stop.
	stopTimeout = 45 * time.Second
)

// winService registers the agent with the Service Control Manager. The service runs
// `<exe> run` as LocalSystem, starts automatically, and is restarted by the SCM if it
// stops unexpectedly (including after an update, when Run returns ErrRestart).
type winService struct{}

// Install creates (or updates) and starts the service. It needs an elevated prompt.
func (winService) Install(exe string) error {
	m, err := connectSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		// Already installed: point it at this binary and make sure it runs.
		defer s.Close()
		cfg, err := s.Config()
		if err != nil {
			return fmt.Errorf("read service config: %w", err)
		}
		cfg.BinaryPathName = windows.EscapeArg(exe) + " run"
		cfg.StartType = mgr.StartAutomatic
		cfg.DisplayName = serviceDisplayName
		cfg.Description = serviceDescription
		if err := s.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("update service config: %w", err)
		}
	} else {
		s, err = m.CreateService(serviceName, exe, mgr.Config{
			DisplayName:  serviceDisplayName,
			Description:  serviceDescription,
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, "run")
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
		defer s.Close()
	}
	if err := setRecovery(s); err != nil {
		return err
	}
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service: %w", err)
	}
	if st.State == svc.Running || st.State == svc.StartPending {
		return nil
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return waitState(s, svc.Running, 30*time.Second)
}

// setRecovery makes the SCM restart the agent 5 s after it stops unexpectedly (30 s from
// the third failure), counting failures over a day, also when the process exits with an
// error code rather than crashing.
func setRecovery(s *mgr.Service) error {
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	if err := s.SetRecoveryActions(actions, uint32((24 * time.Hour).Seconds())); err != nil {
		return fmt.Errorf("set service recovery: %w", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("set service recovery: %w", err)
	}
	return nil
}

// Uninstall stops and deletes the service. It returns platform.ErrUnsupported when no
// service is installed, like the other platforms.
func (winService) Uninstall() error {
	m, err := connectSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return platform.ErrUnsupported
		}
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	// Drop the recovery actions first so the SCM does not restart it while it stops.
	_ = s.ResetRecoveryActions()
	var errs []error
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			errs = append(errs, fmt.Errorf("stop service: %w", err))
		} else if err := waitState(s, svc.Stopped, stopTimeout); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		errs = append(errs, fmt.Errorf("delete service: %w", err))
	}
	return errors.Join(errs...)
}

// Status reports the service state, e.g. "running".
func (winService) Status() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		// Reading the state works unelevated through OpenSCManager with connect rights,
		// which mgr.Connect does not ask for; fall back to a narrower open.
		return queryUnelevated()
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return "not installed", nil
		}
		return "", err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", err
	}
	return stateName(st.State), nil
}

// queryUnelevated opens the SCM and the service with query rights only.
func queryUnelevated() (string, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(h)
	name, _ := windows.UTF16PtrFromString(serviceName)
	sh, err := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return "not installed", nil
		}
		return "", err
	}
	defer windows.CloseServiceHandle(sh)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(sh, &st); err != nil {
		return "", err
	}
	return stateName(svc.State(st.CurrentState)), nil
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "resuming"
	case svc.PausePending:
		return "pausing"
	case svc.Paused:
		return "paused"
	}
	return fmt.Sprintf("state %d", s)
}

func connectSCM() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, errors.New("managing the service needs an elevated prompt (Run as administrator)")
		}
		return nil, fmt.Errorf("connect to the service manager: %w", err)
	}
	return m, nil
}

func waitState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("query service: %w", err)
		}
		if st.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service is %s after %s, expected %s", stateName(st.State), timeout, stateName(want))
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// RunAsService runs fn under the SCM when the process was started by it.
func (winService) RunAsService(fn func(ctx context.Context) error) (bool, error) {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false, nil
	}
	h := &handler{fn: fn}
	if err := svc.Run(serviceName, h); err != nil {
		return true, err
	}
	return true, h.err
}

// handler adapts the agent's Run to the SCM protocol. A stop or shutdown request cancels
// the context; if the agent stops on its own (an update was installed, or it failed), the
// service exits with a service-specific error so the recovery actions restart it.
type handler struct {
	fn  func(ctx context.Context) error
	err error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.fn(ctx) }()
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopTimeout.Milliseconds())}
				cancel()
				select {
				case h.err = <-done:
				case <-time.After(stopTimeout - 5*time.Second):
					h.err = errors.New("agent did not stop in time")
				}
				return false, 0
			}
		case h.err = <-done:
			// Stopped without being asked: let the SCM restart it.
			return true, 1
		}
	}
}

// LogOutput sends the agent's log to <dataDir>\logs\agent.log when it runs as a service,
// where nothing reads stderr. Interactive runs keep logging to the console.
func (winService) LogOutput(dataDir string) (io.Writer, bool) {
	if isSvc, err := svc.IsWindowsService(); err != nil || !isSvc {
		return nil, false
	}
	dir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false
	}
	return &rotatingFile{path: filepath.Join(dir, "agent.log"), max: 10 << 20}, true
}

// rotatingFile appends to path and moves it to path.1 once it exceeds max bytes, so the
// log keeps between max and 2*max bytes of history.
type rotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil || r.size+int64(len(p)) > r.max {
		if err := r.open(r.f != nil); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) open(rotate bool) error {
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
	if fi, err := os.Stat(r.path); err == nil && (rotate || fi.Size() >= r.max) {
		_ = os.Remove(r.path + ".1")
		_ = os.Rename(r.path, r.path+".1")
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}
