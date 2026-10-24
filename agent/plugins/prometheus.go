package plugins

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/example-org/pulsegrid/proto"
)

// A plugin may send at most this many series per run, so a chatty exporter
// can't flood the tenant's storage.
const maxCustomSeries = 1000

var metricName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
var labelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// collectPrometheus scrapes an exporter or an app's /metrics:
// url = http://127.0.0.1:9100/metrics, include = regexp of names (optional).
// Series are stored as pulsegrid_custom_<name>.
func collectPrometheus(ctx context.Context, c Config) ([]proto.Sample, error) {
	url := setting(c, "url", "")
	if url == "" {
		return nil, fmt.Errorf("url is required")
	}
	headers := map[string]string{"Accept": "text/plain;version=0.0.4"}
	if tok := c.Settings["bearer_token"]; tok != "" {
		headers["Authorization"] = "Bearer " + tok
	}
	body, err := get(ctx, url, headers)
	if err != nil {
		return nil, err
	}
	var include *regexp.Regexp
	if p := c.Settings["include"]; p != "" {
		if include, err = regexp.Compile(p); err != nil {
			return nil, fmt.Errorf("include: %w", err)
		}
	}
	return ParseExposition(string(body), include, maxCustomSeries)
}

// ParseExposition parses Prometheus text format (also used by script
// plugins). Histograms and summaries come through as their _sum/_count/
// _bucket series. Timestamps are ignored: the agent stamps the batch.
func ParseExposition(text string, include *regexp.Regexp, limit int) ([]proto.Sample, error) {
	var out []proto.Sample
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s, ok := parseLine(line)
		if !ok {
			continue
		}
		if include != nil && !include.MatchString(s.Name) {
			continue
		}
		s.Name = "pulsegrid_custom_" + strings.TrimPrefix(s.Name, "pulsegrid_custom_")
		out = append(out, s)
		if len(out) >= limit {
			return out, fmt.Errorf("more than %d series; only the first %d were kept (use include = to narrow)", limit, limit)
		}
	}
	return out, sc.Err()
}

func parseLine(line string) (proto.Sample, bool) {
	var s proto.Sample
	name := line
	rest := ""
	if i := strings.IndexAny(line, "{ \t"); i >= 0 {
		name, rest = line[:i], line[i:]
	}
	if !metricName.MatchString(name) {
		return s, false
	}
	s.Name = strings.ReplaceAll(name, ":", "_")
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "{") {
		end := strings.LastIndex(rest, "}")
		if end < 0 {
			return s, false
		}
		labels, ok := parseLabels(rest[1:end])
		if !ok {
			return s, false
		}
		s.Labels = labels
		rest = strings.TrimSpace(rest[end+1:])
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return s, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return s, false
	}
	s.Value = v
	return s, true
}

func parseLabels(s string) (map[string]string, bool) {
	out := map[string]string{}
	for len(strings.TrimSpace(s)) > 0 {
		s = strings.TrimLeft(s, " ,")
		if s == "" {
			break
		}
		eq := strings.Index(s, "=")
		if eq < 0 {
			return nil, false
		}
		k := strings.TrimSpace(s[:eq])
		s = strings.TrimSpace(s[eq+1:])
		if !strings.HasPrefix(s, `"`) {
			return nil, false
		}
		// Find the closing quote, honoring escapes.
		var b strings.Builder
		i := 1
		for ; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				switch s[i] {
				case 'n':
					b.WriteByte('\n')
				default:
					b.WriteByte(s[i])
				}
				continue
			}
			if s[i] == '"' {
				break
			}
			b.WriteByte(s[i])
		}
		if i >= len(s) {
			return nil, false
		}
		// Labels the platform sets itself can't be overridden.
		if labelName.MatchString(k) && k != "tenant_id" && k != "host_id" && k != "plugin" {
			out[k] = b.String()
		}
		s = s[i+1:]
	}
	return out, true
}
