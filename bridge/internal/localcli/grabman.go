package localcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ResolveBinary locates grabman or grabtaculous safely without invoking any shell.
func ResolveBinary(override, toolName string) (string, error) {
	if trimmed := strings.TrimSpace(override); trimmed != "" {
		if st, err := os.Stat(trimmed); err == nil && !st.IsDir() {
			return trimmed, nil
		}
		return "", fmt.Errorf("%s override binary not found at %q", toolName, trimmed)
	}
	if p, err := exec.LookPath(toolName); err == nil {
		return p, nil
	}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	candidates := []string{
		filepath.Join("C:\\Development", toolName, "dist", toolName+"-"+runtime.GOOS+"-"+runtime.GOARCH+suffix),
		filepath.Join("C:\\Development", toolName, toolName+suffix),
		filepath.Join("..", toolName, "dist", toolName+"-"+runtime.GOOS+"-"+runtime.GOARCH+suffix),
		filepath.Join("..", toolName, toolName+suffix),
	}
	for _, cand := range candidates {
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand, nil
		}
	}
	return "", fmt.Errorf("could not locate %s binary in PATH or workspace", toolName)
}

// RunJSONCommand executes an allowlisted binary with explicit argument vector (zero /bin/sh -c).
func RunJSONCommand(ctx context.Context, binPath string, args ...string) (map[string]any, int, string, error) {
	runCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, binPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return nil, 1, stderr.String(), err
		}
	}

	rawOut := strings.TrimSpace(stdout.String())
	if rawOut == "" {
		return map[string]any{"ok": exitCode == 0, "stderr": strings.TrimSpace(stderr.String())}, exitCode, stderr.String(), nil
	}

	var parsed map[string]any
	if jErr := json.Unmarshal([]byte(rawOut), &parsed); jErr != nil {
		return nil, exitCode, stderr.String(), fmt.Errorf("failed to parse JSON from %s %v: %w (raw: %s)", binPath, args, jErr, rawOut)
	}
	return parsed, exitCode, strings.TrimSpace(stderr.String()), nil
}

// Doctor executes `grabman doctor --dir <workspace> [--strict] [--grab-bin <path>] --json`.
func Doctor(ctx context.Context, grabmanBin, workspace, grabBin string, strict bool) (map[string]any, int, error) {
	resolved, err := ResolveBinary(grabmanBin, "grabman")
	if err != nil {
		return nil, 1, err
	}
	args := []string{"doctor", "--dir", workspace, "--json"}
	if strict {
		args = append(args, "--strict")
	}
	if strings.TrimSpace(grabBin) != "" {
		args = append(args, "--grab-bin", strings.TrimSpace(grabBin))
	}
	out, code, _, runErr := RunJSONCommand(ctx, resolved, args...)
	return out, code, runErr
}

// SolveVerify executes `grabman solve --dir <workspace> --verify --json`.
func SolveVerify(ctx context.Context, grabmanBin, workspace string) (map[string]any, int, error) {
	resolved, err := ResolveBinary(grabmanBin, "grabman")
	if err != nil {
		return nil, 1, err
	}
	out, code, _, runErr := RunJSONCommand(ctx, resolved, "solve", "--dir", workspace, "--verify", "--json")
	return out, code, runErr
}

// DNAValidate executes `grabman dna validate <file.json> --json`.
func DNAValidate(ctx context.Context, grabmanBin, filePath string) (map[string]any, int, error) {
	resolved, err := ResolveBinary(grabmanBin, "grabman")
	if err != nil {
		return nil, 1, err
	}
	out, code, _, runErr := RunJSONCommand(ctx, resolved, "dna", "validate", filePath, "--json")
	return out, code, runErr
}

// DNADiff executes `grabman dna diff <old.json> <new.json> --json`.
func DNADiff(ctx context.Context, grabmanBin, oldPath, newPath string) (map[string]any, int, error) {
	resolved, err := ResolveBinary(grabmanBin, "grabman")
	if err != nil {
		return nil, 1, err
	}
	out, code, _, runErr := RunJSONCommand(ctx, resolved, "dna", "diff", oldPath, newPath, "--json")
	return out, code, runErr
}
