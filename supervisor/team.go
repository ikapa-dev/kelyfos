package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/vsock"
)

// teamClient is the guest end of the team channel (docs/protocol.md §5.6).
//
// One connection, held for the life of the sandbox, carrying request/response
// frames to the host broker. It is a client and never a server: no guest
// accepts a connection from another guest, because there is no path for one
// (docs/teams.md §2), and the host is the only participant that knows the edge
// list or can write the audit record.
//
// The guest is told its own name by the host at boot, on the kernel command
// line, for the same reason the proxy address arrives that way: it is the one
// thing in this machine the guest did not write. An agent cannot rename itself
// into another agent's edges.
type teamClient struct {
	agent string

	// maySpawn is what the host said on the kernel command line, not something
	// this process decided: the guest is told whether it has a budget so the
	// tool is listed only where it can work (E2-5).
	maySpawn bool

	mu      sync.Mutex
	conn    net.Conn
	w       *proto.Writer
	r       *proto.Reader
	nextID  int
	dialErr error
}

// newTeamClient reports nil when this sandbox is not part of a team, which is
// the ordinary case and not an error.
func newTeamClient() *teamClient {
	agent := kernelParam("kelyfos.agent")
	if agent == "" {
		return nil
	}
	spawn := kernelParam("kelyfos.spawn") == "1"
	logf("team member %q (spawn budget: %v)", agent, spawn)
	return &teamClient{agent: agent, maySpawn: spawn}
}

// call sends one request and waits for its answer.
//
// Serialised on one connection, because the ordering the spec promises is
// per-edge FIFO and a second connection would be a second order. The lock is
// held across the round trip for the same reason: two tool calls from one agent
// must not interleave their frames.
func (c *teamClient) call(req proto.TeamRequest) (proto.TeamResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connect(); err != nil {
		return proto.TeamResponse{}, err
	}
	c.nextID++
	req.V = proto.Version
	req.ID = fmt.Sprint(c.nextID)

	if err := c.w.Write(req); err != nil {
		c.drop()
		return proto.TeamResponse{}, fmt.Errorf("team channel: %w", err)
	}
	var resp proto.TeamResponse
	if err := c.r.Read(&resp); err != nil {
		c.drop()
		return proto.TeamResponse{}, fmt.Errorf("team channel: %w", err)
	}
	if resp.Error != nil {
		return resp, resp.Error
	}
	return resp, nil
}

// connect dials on first use and after a drop. A snapshot restore severs every
// connection and only the guest can re-dial (docs/protocol.md §1.6), so this
// has to be a reconnect rather than a one-time setup.
func (c *teamClient) connect() error {
	if c.conn != nil {
		return nil
	}
	conn, err := vsock.Dial(proto.CIDHost, proto.PortTeam)
	if err != nil {
		return fmt.Errorf("the team channel is not answering: %w", err)
	}
	c.conn, c.w, c.r = conn, proto.NewWriter(conn), proto.NewReader(conn)
	return nil
}

func (c *teamClient) drop() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn, c.w, c.r = nil, nil, nil
}

// The tool surface. Each is one op on the channel; none of them decides
// anything, because every decision — may this reach that agent, does this
// correlation exist, what goes in the record — belongs to the host.

func (c *teamClient) send(to string, body []byte) error {
	_, err := c.call(proto.TeamRequest{Op: proto.OpTeamSend, To: to,
		Body: base64.StdEncoding.EncodeToString(body)})
	return err
}

func (c *teamClient) recv(timeout time.Duration) (from string, body []byte, correlate string, err error) {
	resp, err := c.call(proto.TeamRequest{Op: proto.OpTeamRecv, TimeoutMS: timeout.Milliseconds()})
	if err != nil {
		return "", nil, "", err
	}
	b, derr := base64.StdEncoding.DecodeString(resp.Body)
	if derr != nil {
		return "", nil, "", fmt.Errorf("the broker sent a body this guest cannot decode: %w", derr)
	}
	return resp.From, b, resp.Correlate, nil
}

func (c *teamClient) ask(to string, body []byte, timeout time.Duration) ([]byte, error) {
	resp, err := c.call(proto.TeamRequest{Op: proto.OpTeamAsk, To: to,
		Body: base64.StdEncoding.EncodeToString(body), TimeoutMS: timeout.Milliseconds()})
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Body)
}

func (c *teamClient) reply(correlate string, body []byte) error {
	_, err := c.call(proto.TeamRequest{Op: proto.OpTeamReply, Correlate: correlate,
		Body: base64.StdEncoding.EncodeToString(body)})
	return err
}

func (c *teamClient) peers() ([]string, error) {
	resp, err := c.call(proto.TeamRequest{Op: proto.OpTeamPeers})
	if err != nil {
		return nil, err
	}
	return resp.Peers, nil
}

func (c *teamClient) spawn(image string) (string, error) {
	resp, err := c.call(proto.TeamRequest{Op: proto.OpTeamSpawn, Image: image})
	if err != nil {
		return "", err
	}
	return resp.Agent, nil
}

func (c *teamClient) storeGet(key string) ([]byte, error) {
	resp, err := c.call(proto.TeamRequest{Op: proto.OpTeamStoreGet, Key: key})
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Body)
}

func (c *teamClient) storePut(key string, body []byte) error {
	_, err := c.call(proto.TeamRequest{Op: proto.OpTeamStorePut, Key: key,
		Body: base64.StdEncoding.EncodeToString(body)})
	return err
}
