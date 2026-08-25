package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// `--check` spawns the server the configuration names and completes a real MCP
// handshake (P6-13).
//
// Because "configured" asserted without evidence is the thing this command
// exists to replace. Writing a file and printing "done" is what a paragraph of
// documentation already did; the difference is that this one starts the server
// it just named and speaks to it.
//
// **What a handshake honestly proves, and what it cannot.** It proves this
// server starts, here, now, and speaks MCP — which is worth having, because the
// most common failure is a binary that is not where the file says it is. It does
// **not** prove the client will find the file, that the client expands the same
// variables, or that the client speaks this era of the protocol. Those are the
// client's business and this command says so rather than implying otherwise.
//
// **Dual-era from the first line.** The current MCP revision removes the
// `initialize` handshake; the revision KelyfOS speaks has it. So this probes
// first and falls back on any other answer, which costs one round trip against
// KelyfOS's own server and needs no rewrite when the revision moves.

const checkTimeout = 20 * time.Second

func checkHandshake(cmd command) error {
	fmt.Printf("\nstarting %s to see whether it answers…\n", cmd.Bin)

	proc := exec.Command(cmd.Bin, cmd.Args...)
	stdin, err := proc.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := proc.StdoutPipe()
	if err != nil {
		return err
	}
	// The server's diagnostics belong to the person running this, not swallowed:
	// when a handshake fails the reason is almost always on stderr.
	proc.Stderr = os.Stderr
	if err := proc.Start(); err != nil {
		return fmt.Errorf("could not start %s: %w", cmd.Bin, err)
	}
	defer func() {
		_ = stdin.Close()
		_ = proc.Process.Kill()
		_ = proc.Wait()
	}()

	answers := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
		for sc.Scan() {
			if len(strings.TrimSpace(sc.Text())) > 0 {
				answers <- sc.Text()
				return
			}
		}
		answers <- ""
	}()

	// The probe: initialize, which the era KelyfOS speaks requires and a later
	// one does not have. An error back is still an answer — it means something
	// is there, speaking JSON-RPC, which is what this is asking.
	req := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "kelyfos-connect", "version": "1"},
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := stdin.Write(append(body, '\n')); err != nil {
		return fmt.Errorf("the server closed its input before the handshake: %w", err)
	}

	select {
	case line := <-answers:
		if line == "" {
			return fmt.Errorf("%s started and then said nothing.\n"+
				"    Its own diagnostics are above, if it printed any", cmd.Bin)
		}
		var resp struct {
			JSONRPC string          `json:"jsonrpc"`
			Result  json.RawMessage `json:"result"`
			Error   json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			return fmt.Errorf("%s answered something that is not JSON-RPC:\n    %s", cmd.Bin, trim(line))
		}
		if resp.JSONRPC != "2.0" {
			return fmt.Errorf("%s answered without a jsonrpc field:\n    %s", cmd.Bin, trim(line))
		}
		switch {
		case len(resp.Error) > 0:
			// An error is a live server that did not like the request, which on
			// a newer protocol revision is exactly what `initialize` gets. The
			// question was whether anything is there.
			fmt.Println("  the server is there and speaking MCP, and refused `initialize` —")
			fmt.Println("  which is what a revision that has removed it does.")
		default:
			fmt.Println("  the server answered the handshake")
		}
	case <-time.After(checkTimeout):
		return fmt.Errorf("%s did not answer within %s.\n"+
			"    On macOS the server runs inside the Lima layer; `kelyfos doctor` says whether it is up",
			cmd.Bin, checkTimeout)
	}

	fmt.Println()
	fmt.Println("  That is what a handshake proves: this server starts, here, now, and speaks MCP.")
	fmt.Println("  It does not prove your client will find the file, expand the same variables,")
	fmt.Println("  or speak this era of the protocol. Those are the client's to get right.")
	return nil
}

func trim(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
