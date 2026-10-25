package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/example-org/pulsegrid/agent/plugins"
	"github.com/example-org/pulsegrid/proto"
)

// Remote actions ("restart nginx when it stops") are opt-in per server. The
// dashboard can only ask for an action by name; what the name runs is set in
// <config dir>/actions.conf, which only root can write:
//
//	restart-nginx = /usr/bin/sudo -n /usr/bin/systemctl restart nginx
//
// `pulsegrid-agent allow-action` writes that file and, on Unix, a sudoers
// rule for exactly that command, since the agent itself is unprivileged.

const (
	actionTimeout   = 2 * time.Minute
	actionOutputMax = 4 << 10
	actionsFile     = "actions.conf"
	sudoersFile     = "/etc/sudoers.d/pulsegrid"
)

var actionName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

// loadActions returns the allowed actions. Problems with the file mean no
// actions: refusing is always safe.
func loadActions(dir string) (map[string][]string, error) {
	path := filepath.Join(dir, actionsFile)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := plugins.CheckOwnership(path); err != nil {
		return nil, err
	}
	kv, err := plugins.ParseKV(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := map[string][]string{}
	for name, cmd := range kv {
		args := strings.Fields(cmd)
		if !actionName.MatchString(name) || len(args) == 0 || !filepath.IsAbs(args[0]) {
			continue
		}
		out[name] = args
	}
	return out, nil
}

func allowedActionNames(m map[string][]string) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// runAction runs one requested action if it's on the allow-list.
func runAction(ctx context.Context, dir string, req proto.ActionRequest) proto.ActionResult {
	res := proto.ActionResult{ID: req.ID, ExitCode: -1}
	allowed, err := loadActions(dir)
	if err != nil {
		res.Status, res.Output = "refused", "actions file unusable: "+err.Error()
		return res
	}
	args, ok := allowed[req.Name]
	if !ok {
		res.Status = "refused"
		res.Output = fmt.Sprintf("%q isn't allowed on this server; an administrator can allow it with: pulsegrid-agent allow-action %s -- <command>", req.Name, req.Name)
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, actionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &cappedWriter{buf: &out, max: actionOutputMax}
	cmd.Stderr = cmd.Stdout
	err = cmd.Run()
	res.Output = strings.TrimSpace(out.String())
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		res.Status, res.ExitCode = "succeeded", 0
	case errors.As(err, &exitErr):
		res.Status, res.ExitCode = "failed", exitErr.ExitCode()
	default:
		res.Status = "failed"
		if res.Output == "" {
			res.Output = err.Error()
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		res.Output = strings.TrimSpace(res.Output + "\n(timed out after " + actionTimeout.String() + ")")
	}
	return res
}

type cappedWriter struct {
	buf *bytes.Buffer
	max int
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		c.buf.Write(p)
	}
	return len(p), nil
}

// cmdAllowAction: pulsegrid-agent allow-action NAME [--sudo] -- COMMAND ARGS...
// Run as root. --sudo (the default on Unix) also lets the agent's user run
// exactly that command as root without a password.
func cmdAllowAction(args []string) error {
	fs := flag.NewFlagSet("allow-action", flag.ExitOnError)
	configDir := fs.String("config-dir", defaultConfigDir(), "agent config directory")
	user := fs.String("user", defaultServiceUser(), "the agent's user, for the sudoers rule")
	noSudo := fs.Bool("no-sudo", runtime.GOOS == "windows", "run the command as the agent's user instead of through sudo")
	remove := fs.Bool("remove", false, "remove the action instead")
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("usage: pulsegrid-agent allow-action NAME -- /absolute/command args")
	}
	name := rest[0]
	if !actionName.MatchString(name) {
		return errors.New("action names are lowercase letters, digits, dot, dash and underscore")
	}
	command := rest[1:]
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if !*remove && (len(command) == 0 || !filepath.IsAbs(command[0])) {
		return errors.New("give the command with an absolute path after --, e.g. -- /usr/bin/systemctl restart nginx")
	}
	if err := os.MkdirAll(*configDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(*configDir, actionsFile)
	existing := map[string]string{}
	if f, err := os.Open(path); err == nil {
		existing, err = plugins.ParseKV(f)
		f.Close()
		if err != nil {
			return err
		}
	}
	if *remove {
		delete(existing, name)
	} else {
		run := command
		if !*noSudo {
			sudo, ok := findTool("sudo")
			if !ok {
				return errors.New("sudo isn't installed; install it or use --no-sudo")
			}
			run = append([]string{sudo, "-n"}, command...)
		}
		existing[name] = strings.Join(run, " ")
	}
	if err := writeActions(path, existing); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := writeSudoers(existing, *user); err != nil {
			return err
		}
		if err := systemdSudoDropIn(usesSudo(existing) || hardwareUsesSudo()); err != nil {
			return err
		}
	}
	if *remove {
		fmt.Printf("Removed action %s\n", name)
	} else {
		fmt.Printf("Allowed action %s: %s\nThe dashboard can now run it on this server.\n", name, existing[name])
	}
	return nil
}

func writeActions(path string, actions map[string]string) error {
	names := make([]string, 0, len(actions))
	for n := range actions {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# Actions the Pulsegrid dashboard may run on this server, by name.\n")
	b.WriteString("# Managed by `pulsegrid-agent allow-action`; only root should edit this file.\n")
	for _, n := range names {
		fmt.Fprintf(&b, "%s = %s\n", n, actions[n])
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// writeSudoers grants the agent's user exactly the sudo commands in the
// actions file, validated with visudo before it's put in place.
func writeSudoers(actions map[string]string, user string) error {
	var lines []string
	for _, cmd := range actions {
		args := strings.Fields(cmd)
		if len(args) > 2 && filepath.Base(args[0]) == "sudo" && args[1] == "-n" {
			lines = append(lines, fmt.Sprintf("%s ALL=(root) NOPASSWD: %s", user, sudoersEscape(strings.Join(args[2:], " "))))
		}
	}
	if len(lines) == 0 {
		err := os.Remove(sudoersFile)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	sort.Strings(lines)
	content := "# Managed by pulsegrid-agent allow-action\n" + strings.Join(lines, "\n") + "\n"
	if _, err := os.Stat(filepath.Dir(sudoersFile)); err != nil {
		return fmt.Errorf("%s doesn't exist; is sudo installed?", filepath.Dir(sudoersFile))
	}
	tmp := sudoersFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o440); err != nil {
		return err
	}
	if visudo, ok := findTool("visudo"); ok {
		if out, err := exec.Command(visudo, "-cf", tmp).CombinedOutput(); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("sudoers rule rejected by visudo: %s", strings.TrimSpace(string(out)))
		}
	}
	return os.Rename(tmp, sudoersFile)
}

// sudoersEscape escapes the characters sudoers treats specially in commands.
func sudoersEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `,`, `\,`, `:`, `\:`, `=`, `\=`)
	return r.Replace(s)
}

func usesSudo(actions map[string]string) bool {
	for _, cmd := range actions {
		if args := strings.Fields(cmd); len(args) > 1 && filepath.Base(args[0]) == "sudo" {
			return true
		}
	}
	return false
}

const (
	agentUnit  = "pulsegrid-agent"
	dropInDir  = "/etc/systemd/system/" + agentUnit + ".service.d"
	dropInFile = dropInDir + "/actions.conf"
)

// systemdSudoDropIn relaxes the agent unit's sandbox only while sudo
// actions are allowed: NoNewPrivileges blocks sudo, and ProtectSystem=strict
// would show the commands it runs a read-only system. Removed again with
// the last such action.
func systemdSudoDropIn(enable bool) error {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil // not systemd
	}
	_, statErr := os.Stat(dropInFile)
	if enable == (statErr == nil) {
		return nil
	}
	if enable {
		if err := os.MkdirAll(dropInDir, 0o755); err != nil {
			return err
		}
		content := "# Written by pulsegrid-agent (allow-action, enable-hardware): sudo needs these.\n" +
			"[Service]\nNoNewPrivileges=false\nProtectSystem=full\n"
		if err := os.WriteFile(dropInFile, []byte(content), 0o644); err != nil {
			return err
		}
	} else if err := os.Remove(dropInFile); err != nil {
		return err
	}
	systemctl, ok := findTool("systemctl")
	if !ok {
		return nil
	}
	if out, err := exec.Command(systemctl, "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command(systemctl, "restart", agentUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("restarting the agent: %s", strings.TrimSpace(string(out)))
	}
	fmt.Println("Restarted the agent so its actions can use sudo.")
	return nil
}
