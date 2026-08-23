package main

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
)

// defaultAskTimeout is how long team_ask waits when the caller does not say.
// Long enough for another agent to think, short enough that a model does not
// sit on a dead conversation for the rest of the run.
const defaultAskTimeout = 60 * time.Second

// teamToolDefinitions are the tools a team member gets on top of the
// ordinary six. They appear only when this sandbox is in a team, because a tool
// that is always listed and always fails teaches a model to ignore failures.
func teamToolDefinitions(maySpawn bool) []mcp.Tool {
	str := func(desc string) mcp.Property { return mcp.Property{Type: "string", Description: desc} }
	tools := []mcp.Tool{
		{
			Name:  "team_send",
			Title: "Send a message to another agent",
			Description: "Deliver a message to another agent in this team. Returns once the host " +
				"has accepted or refused it — refusal is an error naming the reason, and the " +
				"commonest reason is that this team has no edge to that agent. Use `team_peers` " +
				"to see which agents you may reach.",
			InputSchema: mcp.Schema{
				Type:     "object",
				Required: []string{"to", "body"},
				Properties: map[string]mcp.Property{
					"to":   str("The recipient's agent name."),
					"body": str("The message."),
				},
			},
		},
		{
			Name:  "team_recv",
			Title: "Take the next message addressed to you",
			Description: "Wait for the next message from another agent. Returns the sender, the " +
				"body, and — when the message is a question — a `correlate` tag to hand back to " +
				"`team_reply`. Returns an error rather than an empty result when the wait expires.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"timeout_ms": {Type: "integer", Description: "How long to wait. Defaults to 60000."},
				},
			},
		},
		{
			Name:  "team_ask",
			Title: "Ask another agent a question and wait for the answer",
			Description: "Send a question to another agent and block until it answers or the wait " +
				"expires. This is the tool to use when you need something back; `team_send` is for " +
				"when you do not.",
			InputSchema: mcp.Schema{
				Type:     "object",
				Required: []string{"to", "body"},
				Properties: map[string]mcp.Property{
					"to":         str("The agent to ask."),
					"body":       str("The question."),
					"timeout_ms": {Type: "integer", Description: "How long to wait for an answer. Defaults to 60000."},
				},
			},
		},
		{
			Name:  "team_reply",
			Title: "Answer a question another agent asked you",
			Description: "Answer a question that arrived through `team_recv`, using the `correlate` " +
				"tag it came with. You can only answer a question that was put to you, and only " +
				"while the asker is still waiting.",
			InputSchema: mcp.Schema{
				Type:     "object",
				Required: []string{"correlate", "body"},
				Properties: map[string]mcp.Property{
					"correlate": str("The tag from the question you are answering."),
					"body":      str("The answer."),
				},
			},
		},
		{
			Name:  "team_peers",
			Title: "List the agents you can message",
			Description: "The agents this one may send to. It is not a roster of the team: an edge " +
				"can be one-way, and an agent that can reach you does not appear here unless you " +
				"can also reach it.",
			InputSchema: mcp.Schema{Type: "object"},
		},
		{
			Name:        "team_store_get",
			Title:       "Read a key from the team store",
			Description: "Read shared team state. Access is per key and set by the team's policy; a key you may not read is an error, not an empty value.",
			InputSchema: mcp.Schema{
				Type:       "object",
				Required:   []string{"key"},
				Properties: map[string]mcp.Property{"key": str("The key to read.")},
			},
		},
		{
			Name:        "team_store_put",
			Title:       "Write a key to the team store",
			Description: "Write shared team state. Every access is recorded in the session's audit log, permitted or not.",
			InputSchema: mcp.Schema{
				Type:     "object",
				Required: []string{"key", "value"},
				Properties: map[string]mcp.Property{
					"key":   str("The key to write."),
					"value": str("The value."),
				},
			},
		},
	}

	// The spawn tool is listed only for an agent the host gave a budget to.
	// Everything about the budget itself stays host-side; this is only the
	// difference between a tool that can work and one that cannot (E2-5).
	if maySpawn {
		tools = append(tools, mcp.Tool{
			Name:  "team_spawn",
			Title: "Ask for another worker",
			Description: "Request a new worker agent, within the budget this agent's policy granted: " +
				"a count, a list of images and a lifetime the user wrote down before the run. The new " +
				"worker can message you and you can message it; it has no other connection to the " +
				"team. Returns the new agent's name.",
			InputSchema: mcp.Schema{
				Type: "object",
				Properties: map[string]mcp.Property{
					"image": str("Image flavor for the worker. Defaults to the first your budget permits."),
				},
			},
		})
	}
	return tools
}

// callTeamTool dispatches the team tools. Every one of them is a thin pass to
// the host: nothing here decides whether a message may be sent, because the
// guest is not the side that gets to decide.
func callTeamTool(c *teamClient, name string, raw json.RawMessage) *mcp.CallToolResult {
	if c == nil {
		return mcp.Errorf("this sandbox is not part of a team")
	}
	var a struct {
		To        string `json:"to"`
		Body      string `json:"body"`
		Correlate string `json:"correlate"`
		Key       string `json:"key"`
		Value     string `json:"value"`
		Image     string `json:"image"`
		TimeoutMS int64  `json:"timeout_ms"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return mcp.Errorf("bad arguments: %v", err)
	}
	timeout := defaultAskTimeout
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}

	switch name {
	case "team_send":
		if err := c.send(a.To, []byte(a.Body)); err != nil {
			return mcp.Errorf("%v", err)
		}
		return text("delivered to " + a.To)

	case "team_recv":
		from, body, correlate, err := c.recv(timeout)
		if err != nil {
			return mcp.Errorf("%v", err)
		}
		// A question is handed back with its tag, so answering it is one more
		// tool call rather than a protocol a model has to be taught.
		out := map[string]any{"from": from, "body": string(body)}
		if correlate != "" {
			out["correlate"] = correlate
			out["note"] = "this is a question; answer it with team_reply using the correlate above"
		}
		return structured(string(body), out)

	case "team_ask":
		answer, err := c.ask(a.To, []byte(a.Body), timeout)
		if err != nil {
			return mcp.Errorf("%v", err)
		}
		return text(string(answer))

	case "team_reply":
		if err := c.reply(a.Correlate, []byte(a.Body)); err != nil {
			return mcp.Errorf("%v", err)
		}
		return text("answered")

	case "team_peers":
		name, peers, err := c.peers()
		if err != nil {
			return mcp.Errorf("%v", err)
		}
		return structured(strings.Join(peers, " "), map[string]any{"agent": name, "peers": peers})

	case "team_spawn":
		// Not refused here even when this agent has no budget: the host is the
		// side that decides, and a refusal it never sees is a refusal that
		// never reaches the log. docs/teams.md §5 promises that a spawn by an
		// agent with no budget at all is audited too.
		name, err := c.spawn(a.Image)
		if err != nil {
			return mcp.Errorf("%v", err)
		}
		return structured(name, map[string]any{"agent": name,
			"note": "this worker can message you and you can message it; it has no other edges"})

	case "team_store_get":
		v, err := c.storeGet(a.Key)
		if err != nil {
			return mcp.Errorf("%v", err)
		}
		return text(string(v))

	case "team_store_put":
		if err := c.storePut(a.Key, []byte(a.Value)); err != nil {
			return mcp.Errorf("%v", err)
		}
		return text("stored " + a.Key)
	}
	return mcp.Errorf("unknown team tool %q", name)
}

// isTeamTool reports whether a tool name belongs to this file, so the dispatch
// in mcp.go stays one switch rather than two lists that can disagree.
func isTeamTool(name string) bool {
	rest, ok := strings.CutPrefix(name, "team_")
	return ok && rest != ""
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{mcp.Text(s)}}
}

// structured returns the same answer twice: as text a model reads, and as
// fields a program reads. The tools that return more than one value need both,
// and returning only the JSON would make a model parse its own tool output.
func structured(s string, fields map[string]any) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content:           []mcp.Content{mcp.Text(s)},
		StructuredContent: fields,
	}
}
