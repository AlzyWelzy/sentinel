//go:build !windows

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/example-org/pulsegrid/agent/plugins"
)

// autoconfigRev is bumped when autoconfig learns something new, so servers
// that already ran an older revision run it again on their next update.
const (
	autoconfigRev    = "2"
	autoconfigMarker = ".autoconfig" // in the config dir: the revision, or "off"
	autoconfigNote   = "# Written by pulsegrid-agent autoconfig. Delete this line before editing, or updates may refresh the file."
)

// cmdAutoconfig: pulsegrid-agent autoconfig [--no-logs] [--off]. Run as root.
// Finds what runs on this server (journal and log files, Redis, nginx,
// Apache, Docker, PostgreSQL, MySQL/MariaDB, SMART/IPMI) and writes the
// config for each. Files that already exist are left alone.
func cmdAutoconfig(args []string) error {
	fs := flag.NewFlagSet("autoconfig", flag.ExitOnError)
	configDir := fs.String("config-dir", defaultConfigDir(), "agent config directory")
	svcUser := fs.String("user", defaultServiceUser(), "the agent's user")
	noLogs := fs.Bool("no-logs", false, "don't ship any logs")
	off := fs.Bool("off", false, "never autoconfigure this server (updates included)")
	fs.Parse(args)
	if os.Geteuid() != 0 {
		return errors.New("run as root: sudo pulsegrid-agent autoconfig")
	}
	marker := filepath.Join(*configDir, autoconfigMarker)
	if *off {
		return os.WriteFile(marker, []byte("off\n"), 0o644)
	}
	if !autoconfigure(*configDir, *svcUser, *noLogs) {
		fmt.Println("Nothing new to set up.")
	}
	return os.WriteFile(marker, []byte(autoconfigRev+"\n"), 0o644)
}

// maybeAutoconfigure runs from the (root) update job, so servers installed
// before autoconfig existed get it once without anyone logging in. It reports
// whether anything was written, i.e. whether the agent should restart.
func maybeAutoconfigure() bool {
	if os.Geteuid() != 0 {
		return false
	}
	dir := defaultConfigDir()
	marker := filepath.Join(dir, autoconfigMarker)
	b, _ := os.ReadFile(marker)
	if m := strings.TrimSpace(string(b)); m == "off" || m == autoconfigRev {
		return false
	}
	changed := autoconfigure(dir, defaultServiceUser(), false)
	os.WriteFile(marker, []byte(autoconfigRev+"\n"), 0o644)
	return changed
}

func autoconfigure(dir, svcUser string, noLogs bool) bool {
	pdir := filepath.Join(dir, "plugins.d")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		fmt.Println("autoconfig:", err)
		return false
	}
	changed := false
	note := func(ok bool, what string) {
		if ok {
			changed = true
			fmt.Println("autoconfig: " + what)
		}
	}
	if !noLogs {
		lc := filepath.Join(dir, "logs.conf")
		note(writeNew(lc, logsConf(), 0o644, "") || refreshLogsConf(lc), "log shipping on: journal and /var/log")
	}
	if portFree("127.0.0.1:4318") {
		note(writeNew(filepath.Join(dir, "apm.conf"), autoconfigNote+"\nlisten = 127.0.0.1:4318\n", 0o644, ""), "APM receiver on 127.0.0.1:4318")
	}

	have := pluginTypes(pdir)
	try := func(typ, conf string, mode os.FileMode, group string, check bool) {
		if have[typ] {
			return
		}
		path := filepath.Join(pdir, typ+".conf")
		if !writeNew(path, autoconfigNote+"\ntype = "+typ+"\n"+conf, mode, group) {
			return
		}
		if check {
			if err := probePlugin(path); err != nil {
				os.Remove(path)
				fmt.Printf("autoconfig: %s found but not readable (%v); skipped\n", typ, err)
				return
			}
		}
		have[typ] = true
		note(true, typ+" monitoring on")
	}

	if dial("127.0.0.1:6379") {
		try("redis", "address = 127.0.0.1:6379\n", 0o644, "", true)
	}
	if url := nginxStatus(); url != "" {
		try("nginx", "url = "+url+"\n", 0o644, "", true)
	}
	if apacheInstalled() && dial("127.0.0.1:80") {
		try("apache", "url = http://127.0.0.1/server-status?auto\n", 0o644, "", true)
	}
	if sock := firstExisting("/var/run/docker.sock", "/run/docker.sock"); sock != "" && !have["docker"] {
		// The docker group is root-equivalent; the agent only reads container stats.
		addToGroup(svcUser, "docker")
		try("docker", "socket = "+sock+"\n", 0o644, "", false)
	}
	if !have["postgres"] {
		if dsn := setupPostgres(svcUser); dsn != "" {
			try("postgres", "dsn = "+dsn+"\n", 0o644, "", false)
		}
	}
	if !have["mysql"] {
		if dsn := setupMySQL(svcUser); dsn != "" {
			try("mysql", "dsn = "+dsn+"\n", 0o640, svcUser, true)
		}
	}
	if !have["smart"] && !have["ipmi"] {
		_, s := findTool("smartctl")
		_, i := findTool("ipmitool")
		if (s || i) && cmdEnableHardware([]string{"--config-dir", dir, "--user", svcUser}) == nil {
			changed = true
		}
	}
	return changed
}

// logsConf ships the journal (where there is one) and every text log under
// /var/log; the agent skips rotated copies, binary files and, with the
// journal on, rsyslog's copies of it.
func logsConf() string {
	var b strings.Builder
	b.WriteString(autoconfigNote + "\n# Comment every line out to stop shipping.\n")
	if _, ok := findTool("journalctl"); ok && exists("/run/systemd/system") {
		b.WriteString("journal = true\n")
	}
	b.WriteString("dir = /var/log\n")
	return b.String()
}

// refreshLogsConf rewrites a logs.conf that autoconfig wrote and nobody
// edited (its first line is still our note), so new revisions reach it.
func refreshLogsConf(path string) bool {
	b, err := os.ReadFile(path)
	ours := strings.HasPrefix(string(b), autoconfigNote+"\n") ||
		strings.HasPrefix(string(b), "# Written by pulsegrid-agent autoconfig. Edit freely; it is never overwritten.\n") // rev 1
	if err != nil || !ours {
		return false
	}
	want := logsConf()
	if string(b) == want {
		return false
	}
	return os.WriteFile(path, []byte(want), 0o644) == nil
}

// nginxStatus finds a stub_status page, adding a local-only one if nginx
// has none. A config nginx rejects is removed again.
func nginxStatus() string {
	nginx, ok := findTool("nginx")
	if !ok {
		return ""
	}
	urls := []string{"http://127.0.0.1/nginx_status", "http://127.0.0.1/stub_status", "http://127.0.0.1:8899/stub_status"}
	for _, u := range urls {
		if httpOK(u) {
			return u
		}
	}
	conf := "/etc/nginx/conf.d/pulsegrid-status.conf"
	if !exists("/etc/nginx/conf.d") || exists(conf) {
		return ""
	}
	body := autoconfigNote + "\n# Local-only status page for the Pulsegrid agent.\n" +
		"server {\n    listen 127.0.0.1:8899;\n    access_log off;\n    location = /stub_status { stub_status; }\n}\n"
	if os.WriteFile(conf, []byte(body), 0o644) != nil {
		return ""
	}
	if exec.Command(nginx, "-t").Run() != nil || exec.Command(nginx, "-s", "reload").Run() != nil {
		os.Remove(conf)
		return ""
	}
	time.Sleep(2 * time.Second)
	if httpOK(urls[2]) {
		return urls[2]
	}
	return ""
}

// setupPostgres gives the agent's OS user a login role with pg_monitor; it
// connects over the local socket with peer auth, so no password is stored.
func setupPostgres(svcUser string) string {
	psql, ok := findTool("psql")
	if !ok {
		return ""
	}
	if _, err := user.Lookup("postgres"); err != nil {
		return ""
	}
	sock := firstExisting("/var/run/postgresql", "/run/postgresql", "/tmp/.s.PGSQL.5432")
	if sock == "" {
		return ""
	}
	if strings.HasSuffix(sock, ".5432") {
		sock = "/tmp"
	}
	sql := fmt.Sprintf(`DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%[1]s') THEN CREATE ROLE "%[1]s" LOGIN; END IF; END$$;
GRANT pg_monitor TO "%[1]s";
`, svcUser)
	cmd := exec.Command("su", "-s", "/bin/sh", "postgres", "-c", psql+" -X -q -v ON_ERROR_STOP=1 -d postgres")
	cmd.Stdin = strings.NewReader(sql)
	cmd.Dir = "/"
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("autoconfig: postgres found but the role couldn't be created: %s\n", strings.TrimSpace(string(out)))
		return ""
	}
	return fmt.Sprintf("host=%s user=%s dbname=postgres", sock, svcUser)
}

// setupMySQL creates a 'pulsegrid'@'localhost' user with a random password
// (stored 0640 for the agent's group), using root's local socket login.
func setupMySQL(svcUser string) string {
	client, ok := findTool("mysql")
	if !ok {
		if client, ok = findTool("mariadb"); !ok {
			return ""
		}
	}
	sock := firstExisting("/run/mysqld/mysqld.sock", "/var/run/mysqld/mysqld.sock", "/var/lib/mysql/mysql.sock", "/tmp/mysql.sock")
	if sock == "" {
		return ""
	}
	buf := make([]byte, 16)
	rand.Read(buf)
	pw := hex.EncodeToString(buf)
	sql := fmt.Sprintf(`CREATE USER IF NOT EXISTS 'pulsegrid'@'localhost' IDENTIFIED BY '%[1]s';
ALTER USER 'pulsegrid'@'localhost' IDENTIFIED BY '%[1]s';
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'pulsegrid'@'localhost';
`, pw)
	cmd := exec.Command(client, "-u", "root", "--protocol=socket", "-S", sock)
	cmd.Stdin = strings.NewReader(sql)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("autoconfig: MySQL found but root can't log in over the socket: %s\n", strings.TrimSpace(string(out)))
		return ""
	}
	return fmt.Sprintf("pulsegrid:%s@unix(%s)/", pw, sock)
}

func probePlugin(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	settings, err := plugins.ParseKV(f)
	f.Close()
	if err != nil {
		return err
	}
	c := plugins.Config{Name: "probe", Type: settings["type"], Settings: settings, Path: path}
	r := plugins.Collect(context.Background(), []plugins.Config{c})
	if !r[0].Status.OK {
		return errors.New(r[0].Status.Error)
	}
	return nil
}

// pluginTypes lists the types already configured, so a plugin the owner set
// up under any file name is never doubled.
func pluginTypes(dir string) map[string]bool {
	have := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		if s, err := plugins.ParseKV(f); err == nil {
			have[strings.ToLower(s["type"])] = true
		}
		f.Close()
	}
	return have
}

// writeNew creates path only if it doesn't exist, root-owned (group, if set,
// may read it). It reports whether it wrote.
func writeNew(path, body string, mode os.FileMode, group string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return false
	}
	_, err = f.WriteString(body)
	f.Close()
	if err != nil {
		os.Remove(path)
		return false
	}
	gid := 0
	if group != "" {
		if g, err := user.LookupGroup(group); err == nil {
			gid, _ = strconv.Atoi(g.Gid)
		} else if u, err := user.Lookup(group); err == nil {
			gid, _ = strconv.Atoi(u.Gid)
		}
	}
	os.Chown(path, 0, gid)
	os.Chmod(path, mode)
	return true
}

func addToGroup(u, g string) {
	if p, ok := findTool("usermod"); ok {
		exec.Command(p, "-aG", g, u).Run()
	} else if p, ok := findTool("adduser"); ok {
		exec.Command(p, u, g).Run()
	} else if p, ok := findTool("pw"); ok {
		exec.Command(p, "groupmod", g, "-m", u).Run()
	}
}

func apacheInstalled() bool {
	for _, t := range []string{"apache2", "httpd", "apachectl"} {
		if _, ok := findTool(t); ok {
			return true
		}
	}
	return false
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if exists(p) {
			return p
		}
	}
	return ""
}

func dial(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func portFree(addr string) bool {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	l.Close()
	return true
}

func httpOK(url string) bool {
	return probePluginSettings(map[string]string{"type": "nginx", "url": url}) == nil
}

func probePluginSettings(s map[string]string) error {
	r := plugins.Collect(context.Background(), []plugins.Config{{Name: "probe", Type: s["type"], Settings: s}})
	if !r[0].Status.OK {
		return errors.New(r[0].Status.Error)
	}
	return nil
}
