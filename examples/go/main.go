package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jingkaihe/matchlock/pkg/sdk"
)

func main() {
	cfg := sdk.DefaultConfig()
	if os.Getenv("MATCHLOCK_BIN") == "" {
		cfg.BinaryPath = "./bin/matchlock"
	}

	client, err := sdk.NewClient(cfg)
	if err != nil {
		slog.Error("failed to create client", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	sandbox := sdk.New("python:3.12-alpine").
		AllowHost(
			"dl-cdn.alpinelinux.org",
			"files.pythonhosted.org", "pypi.org",
			"astral.sh", "github.com", "objects.githubusercontent.com",
			"api.anthropic.com",
		).
		AddSecret("ANTHROPIC_API_KEY", os.Getenv("ANTHROPIC_API_KEY"), "api.anthropic.com")

	vmID, err := client.Launch(sandbox)
	if err != nil {
		slog.Error("failed to launch sandbox", "error", err)
		os.Exit(1)
	}
	slog.Info("sandbox ready", "vm", vmID)

	// Buffered exec — collects all output, returns when done
	run(client, "python3 --version")

	// Install uv
	run(client, "pip install --quiet uv")

	// Write a Python script that uses the Anthropic SDK to stream plain text
	script := `# /// script
# requires-python = ">=3.12"
# dependencies = ["anthropic"]
# ///
import anthropic, os

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
with client.messages.stream(
    model="claude-haiku-4-5-20251001",
    max_tokens=1000,
    messages=[{"role": "user", "content": "Explain TCP to me"}],
) as stream:
    for text in stream.text_stream:
        print(text, end="", flush=True)
print()
`
	if err := client.WriteFile("/workspace/ask.py", []byte(script)); err != nil {
		slog.Error("write_file failed", "error", err)
		os.Exit(1)
	}

	// Streaming exec — prints plain text as it arrives
	result, err := client.ExecStream(
		"uv run /workspace/ask.py",
		os.Stdout, os.Stderr,
	)
	if err != nil {
		slog.Error("exec_stream failed", "error", err)
		os.Exit(1)
	}
	fmt.Println()
	slog.Info("done", "exit_code", result.ExitCode, "duration_ms", result.DurationMS)
}

func run(c *sdk.Client, cmd string) {
	result, err := c.Exec(cmd)
	if err != nil {
		slog.Error("exec failed", "cmd", cmd, "error", err)
		os.Exit(1)
	}
	fmt.Print(result.Stdout)
}
