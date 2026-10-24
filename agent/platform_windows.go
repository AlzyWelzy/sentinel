//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const exeSuffix = ".exe"

func defaultStateDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Pulsegrid")
}

// runAsService runs the agent under the Windows Service Control Manager when
// started by it (install.ps1 registers the service); from a console it
// reports false and the caller runs in the foreground.
func runAsService(run func(context.Context)) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, err
	}
	return true, svc.Run(serviceName, &service{run: run})
}

const serviceName = "pulsegrid-agent"

func defaultConfigDir() string { return filepath.Join(defaultStateDir(), "conf") }

func defaultServiceUser() string { return "LocalService" }

// findTool is only used for sudo/visudo, which Windows doesn't have.
func findTool(string) (string, bool) { return "", false }

type service struct {
	run func(context.Context)
}

func (s *service) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.run(ctx)
		close(done)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		case <-done:
			cancel()
			return false, 0
		}
	}
}

// replaceExecutable: Windows refuses to overwrite or delete a running .exe
// but does allow renaming it, so the running binary is moved aside first and
// the leftover is cleaned up by the next update.
func replaceExecutable(newPath, target string) error {
	old := target + ".old"
	os.Remove(old)
	if err := os.Rename(target, old); err != nil {
		return fmt.Errorf("moving the running binary aside: %w", err)
	}
	if err := os.Rename(newPath, target); err != nil {
		os.Rename(old, target) // put it back; the service keeps working
		return err
	}
	return nil
}

func restartService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if st, err := s.Query(); err == nil && st.State == svc.Stopped {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	return s.Start()
}
