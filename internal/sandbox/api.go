package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// api talks to a Firecracker instance over its API socket.
//
// Phase 1 booted with --no-api and a config file, which is the simplest thing
// that works when a machine only ever needs to start and stop. Snapshots need
// more than that — pause, create, load, resume — so the API socket is now always
// present. It stays a separate socket from the vsock UDS, with an unrelated
// protocol: this one carries HTTP (docs/protocol.md §1).
//
// Every state-changing call reports itself through onAction (audit
// 2026-09-01, A11): pause, resume, snapshot create and load, drive patch were
// invisible to the transcript, while the API socket itself stays reachable by
// any same-uid process on the host — a VMM action a reader cannot see is a
// VMM action nobody can distinguish from one the record's owner made.
type api struct {
	c        *http.Client
	onAction func(action string)
}

func newAPI(socketPath string) *api {
	return &api{c: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}}
}

// report fires once per state-changing API call, with the action's name.
func (a *api) report(action string) {
	if a.onAction != nil {
		a.onAction(action)
	}
}

func (a *api) do(method, path string, body any) error {
	var buf io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(blob)
	}
	req, err := http.NewRequest(method, "http://localhost"+path, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.c.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: firecracker returned %s: %s",
			method, path, resp.Status, bytes.TrimSpace(detail))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// waitReady polls until the API socket answers, because Firecracker creates it
// a moment after the process starts.
func (a *api) waitReady(ctx context.Context) error {
	for {
		if err := a.do(http.MethodGet, "/version", nil); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("firecracker API socket never answered: %w", ctx.Err())
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func (a *api) pause() error {
	a.report("pause")
	return a.do(http.MethodPatch, "/vm", map[string]string{"state": "Paused"})
}

func (a *api) resume() error {
	a.report("resume")
	return a.do(http.MethodPatch, "/vm", map[string]string{"state": "Resumed"})
}

// createSnapshot writes the machine state and a full copy of guest memory.
// The microVM must already be paused.
func (a *api) createSnapshot(statePath, memPath string) error {
	a.report("snapshot.create")
	return a.do(http.MethodPut, "/snapshot/create", map[string]string{
		"snapshot_type": "Full",
		"snapshot_path": statePath,
		"mem_file_path": memPath,
	})
}

// memBackend and snapshotLoad mirror Firecracker's load request.
type memBackend struct {
	BackendPath string `json:"backend_path"`
	BackendType string `json:"backend_type"`
}

type vsockOverride struct {
	UDSPath string `json:"uds_path"`
}

type snapshotLoad struct {
	SnapshotPath  string         `json:"snapshot_path"`
	MemBackend    memBackend     `json:"mem_backend"`
	ResumeVM      bool           `json:"resume_vm"`
	VsockOverride *vsockOverride `json:"vsock_override,omitempty"`
	// NetworkOverrides re-pairs each virtio-net device to a TAP that exists
	// now. The snapshot records the TAP it was taken with, and that device is
	// gone by the time anyone restores — so without this the load fails inside
	// Firecracker with an ifreq error rather than anywhere useful (D22).
	NetworkOverrides []networkOverride `json:"network_overrides,omitempty"`
}

type networkOverride struct {
	IfaceID     string `json:"iface_id"`
	HostDevName string `json:"host_dev_name"`
}

// patchDrive repoints a block device after the machine exists but before it
// runs. Firecracker documents PATCH /drives as post-boot only, and a
// snapshot-loaded VM that has not been resumed qualifies — which is what lets N
// forks of one snapshot each get their own workspace disk.
func (a *api) patchDrive(driveID, pathOnHost string) error {
	a.report("drive.patch")
	return a.do(http.MethodPatch, "/drives/"+driveID, map[string]string{
		"drive_id":     driveID,
		"path_on_host": pathOnHost,
	})
}

// loadSnapshot restores a machine.
//
// VsockOverride is what makes forking possible at all: two VMs restored from one
// snapshot cannot share a vsock socket path, so each restore is given its own
// (docs/protocol.md §1.6).
func (a *api) loadSnapshot(req snapshotLoad) error {
	a.report("snapshot.load")
	return a.do(http.MethodPut, "/snapshot/load", req)
}
