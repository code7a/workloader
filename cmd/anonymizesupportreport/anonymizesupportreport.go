package anonymizesupportreport

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	cabinet "github.com/abemedia/go-cabinet"
	sevenzip "github.com/bodgit/sevenzip"
	"github.com/brian1917/workloader/utils"
	dbzip2 "github.com/dsnet/compress/bzip2"
	rardecode "github.com/nwaples/rardecode/v2"
	"github.com/spf13/cobra"
	"github.com/ulikunitz/xz"
)

var inputFile string
var allowUnscanned bool

// CLI command
var AnonymizeSupportReportCmd = &cobra.Command{
	Use:   "anonymize-support-report",
	Short: "Redact sensitive data (IPs, hostnames, emails, secrets, names) from a support report before sharing it.",
	Long: `
Scans a support report and replaces sensitive values with consistent placeholder tokens (e.g. IPV4_000001, HOST_000002), then repacks it in its original format so it's safe to share.

What gets redacted:
  - IPv4 and IPv6 addresses
  - Hostnames and FQDNs, including short structured values in fields like hostname=, host:, computer_name, node_name, fqdn, and agent.hostname
  - Email addresses
  - Secrets and tokens: JWTs, AWS access keys, GitHub/Slack tokens, Bearer/Basic Authorization headers, Cookie/Set-Cookie header values, api_key/access_token/client_secret/password-style key=value and JSON fields, and PEM-encoded private key blocks (RSA/DSA/EC/OPENSSH)
  - Personal names in common JSON fields (first_name, last_name, display_name, author, owner, etc.)

Input can be:
  - A single text file, including .har
  - A single compressed file: .gz, .bz2, .xz
  - An archive: .zip, .tar, .tar.gz/.tgz, .tar.bz2, .tar.xz, .cab, .7z, .rar, .docx, .xlsx, .pptx

Archives are extracted, scanned recursively (including archives nested inside archives, with no depth limit), and repacked in the same format - 7z and rar are repacked as .zip since neither can be rewritten in their original format.

Files that can't be scanned (not valid text, and not a recognized archive) and nested archives that fail to extract (corrupt, encrypted, or an unsupported codec) are REMOVED entirely from the anonymized output by default, since shipping unscanned content unmodified could leak whatever it contains. Use --allow-unscanned to keep them in the output unmodified instead - the run log always states exactly what was removed or kept, by file extension.

.db (SQLite) files are always removed entirely rather than redacted or kept: redacting a match in place can corrupt a SQLite database's fixed internal page offsets, so removal is the only safe option. Review the original .db file directly if its content needs checking.

Output:
  - <input>.anonymized.<ext> - the redacted, repacked file/archive
  - <input>.anonymized.<ext>.mapping.json - every original value mapped to its placeholder, by category. This file contains the ACTUAL sensitive values removed from the output - keep it local, do not share it alongside the anonymized file.

Every run also writes a log (see --log-file) with a summary line covering files scanned, nested archives recursed, files/archives removed, and counts redacted per category - a run always produces this line even when nothing needed redaction.`,
	Example: `# Anonymize a single support bundle
  workloader anonymize-support-report --input support_report.tar.gz

  # Anonymize a single log file
  workloader anonymize-support-report --input agent.log

  # Keep files that couldn't be scanned in the output instead of removing them
  workloader anonymize-support-report --input support_report.zip --allow-unscanned`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return Execute(inputFile, allowUnscanned)
	},
}

func init() {
	AnonymizeSupportReportCmd.Flags().StringVar(&inputFile, "input", "", "Path to the file or archive to anonymize (required)")
	_ = AnonymizeSupportReportCmd.MarkFlagRequired("input")
	AnonymizeSupportReportCmd.Flags().BoolVar(&allowUnscanned, "allow-unscanned", false,
		"Keep files/nested archives that could not be scanned for sensitive data in the anonymized output, unmodified (default: remove them entirely)")
}

// Regex definitions
var (
	ipv4Regex       = regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Regex       = regexp.MustCompile(`\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b`)
	emailRegex      = regexp.MustCompile(`[\w\.-]+@[\w\.-]+\.\w+`)
	hostFQDNRegex   = regexp.MustCompile(`\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)
	hostSimpleRegex = regexp.MustCompile(`\b[a-zA-Z0-9-]{6,}\b`)

	// Matches a hostname-shaped value immediately following a literal
	// underscore, capturing just the hostname part (group 1) - see the
	// underscoreHostnameRegex pass in Replace() for why hostFQDNRegex above
	// can't reach this case on its own. Deliberately mirrors hostFQDNRegex's
	// own char class/structure (rather than a stricter per-label pattern)
	// since that shape is already proven correct for greedy multi-label
	// domain matching elsewhere in this file.
	underscoreHostnameRegex = regexp.MustCompile(`_([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)

	timeRegex       = regexp.MustCompile(`^\d{1,2}:\d{2}(:\d{2})?$`)
	numberFileRegex = regexp.MustCompile(`^\d+\.\w+$`)

	isoDateRegex   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(T\d{2}([:-]\d{2}){0,2})?$`)
	numericRegex   = regexp.MustCompile(`^\d+$`)
	hashRegex      = regexp.MustCompile(`^[a-f0-9]{16,}$`)
	alphaRegex     = regexp.MustCompile(`[a-zA-Z]`)
	lowerWordRegex = regexp.MustCompile(`^[a-z]+$`)
	camelCaseRegex = regexp.MustCompile(`^[a-z]+[A-Z][a-zA-Z0-9]+$`)

	uuidRegex     = regexp.MustCompile(`^[a-f0-9\-]{8,}$`)
	startValidReg = regexp.MustCompile(`^[a-zA-Z0-9]`)
	longHexRegex  = regexp.MustCompile(`^[a-f0-9]{12,}$`)

	// A single Title Case word (e.g. "Authorization", "Timestamp") - real
	// hostnames don't look like this; they're lowercase and/or contain
	// digits/hyphens per DNS convention.
	titleCaseWordRegex = regexp.MustCompile(`^[A-Z][a-z]+$`)

	// A PascalCase compound word - two or more Title-Case segments run
	// together with no separator, digits, or hyphens (e.g. "ProgramData",
	// "LastWriteTime", "UserProfile"). Extremely common as Windows
	// environment variable/folder names and PowerShell object property
	// names (Get-Item/Get-ChildItem output), which show up constantly in
	// Windows agent bundle dumps - but not a real hostname shape: like the
	// digit-free kebabWordRegex case below, a real bare hostname (no domain
	// suffix) almost always carries a numeric qualifier to stay unique
	// across a fleet.
	pascalCaseCompoundRegex = regexp.MustCompile(`^[A-Z][a-z0-9]+([A-Z][a-z0-9]+)+$`)

	// A TitleCase word (or PascalCase compound) ending in a trailing 2+
	// letter ALL-CAPS acronym run, e.g. "ManagedOOM" (a real systemd unit
	// property - confirmed leaking through in a real "io.system.ManagedOOM"
	// value once the dotted prefix around it stopped being redacted whole).
	// pascalCaseCompoundRegex above doesn't catch this shape: it requires
	// every segment after the first to itself start uppercase-then-lower/
	// digit, which a bare trailing acronym ("OOM") doesn't satisfy. Real
	// hostnames don't take this shape either - DNS labels ending in a run
	// of bare uppercase letters with no digit/hyphen anywhere are not a
	// convention seen in practice, same reasoning as pascalCaseCompoundRegex.
	acronymSuffixedWordRegex = regexp.MustCompile(`^[A-Z][a-z0-9]*([A-Z][a-z0-9]+)*[A-Z]{2,}$`)

	// Rotated/dated log artifact names, e.g. "log-20260804-1785873540",
	// "perflog-20260711-1783735140", "consul-20260804-1785873540".
	timestampedArtifactRegex = regexp.MustCompile(`^[a-zA-Z]+-\d{8}-\d{9,10}$`)

	// A bare, all-lowercase, hyphen-separated word with no digits, e.g.
	// "illumio-pce", "host-inventory", "fluentd-reporting". Real bare
	// hostnames (no domain suffix) almost always carry a numeric qualifier
	// to stay unique across a fleet; digit-free hyphenated words are far
	// more often directory/service/label names from bundle content.
	kebabWordRegex = regexp.MustCompile(`^[a-z]+(-[a-z]+)+$`)

	// git describe --long's "<commits-since-tag>-<commit-count>-g<abbrev-hash>"
	// suffix (e.g. "4-0-gd6d73eb8", from a version string like
	// "v1.3.4-0-gd6d73eb8"). Has both digits and hyphens, so - unlike
	// kebabWordRegex above - it isn't excluded by any digit-free-only check;
	// confirmed leaving these mistaken for hostnames in runtime/build
	// version strings (containerd, runc, etc.) in real bundle data.
	gitDescribeSuffixRegex = regexp.MustCompile(`^\d+-\d+-g[0-9a-f]{7,40}$`)

	// ANSI junk like 32mSUCCESS
	ansiRegex = regexp.MustCompile(`^\d{1,2}m[A-Z]+$`)

	// Tokens / API keys / secrets
	jwtRegex          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	awsAccessKeyRegex = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	githubTokenRegex  = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)
	slackTokenRegex   = regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)
	bearerAuthRegex   = regexp.MustCompile(`(?i)(authorization"?\s*[:=]\s*"?bearer\s+)([A-Za-z0-9\-._~+/]+=*)`)
	basicAuthRegex    = regexp.MustCompile(`(?i)(authorization"?\s*[:=]\s*"?basic\s+)([A-Za-z0-9+/]+=*)`)
	secretKVRegex     = regexp.MustCompile(`(?i)"(api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|token)"\s*:\s*"([^"]*)"`)

	// Cookie/Set-Cookie header values (HAR headers, curl -v/-i output, proxy
	// logs). The whole value is redacted as one blob rather than parsed into
	// individual cookie=value pairs, since a session cookie is sensitive
	// regardless of its name.
	cookieHeaderRegex = regexp.MustCompile(`(?i)("?(?:cookie|set-cookie)"?\s*[:=]\s*"?)([^"\r\n]+)`)

	// Secrets carried as key=value pairs in a URL query string or an
	// application/x-www-form-urlencoded body - structurally identical
	// wherever they appear (a HAR query/postData dump, a proxy access log,
	// etc.), so one pattern covers both instead of two near-duplicates.
	secretEqualsKVRegex = regexp.MustCompile(`(?i)\b(access_token|refresh_token|id_token|api_key|apikey|client_secret|password|token|secret|session|csrf|xsrf)=([^&\s"'<>]+)`)

	// PEM-encoded private key blocks (RSA/DSA/EC/OPENSSH/generic). OpenSSH's
	// "-----BEGIN OPENSSH PRIVATE KEY-----" already matches the general
	// "[A-Z ]*PRIVATE KEY" header, so one pattern covers both instead of two
	// overlapping regexes.
	pemPrivateKeyRegex = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)

	// Personal names (JSON key/value pairs commonly found in HAR headers/cookies/postData)
	nameKVRegex = regexp.MustCompile(`(?i)"(first[_-]?name|last[_-]?name|full[_-]?name|display[_-]?name|user[_-]?name|author|owner)"\s*:\s*"([^"]*)"`)

	// The plain-text (not JSON-quoted) equivalent of nameKVRegex above, for
	// Windows systeminfo.exe's "Registered Owner:"/"Registered
	// Organization:"/"OS Manufacturer:"/"System Manufacturer:" fields - each
	// alone on its own line, padded with spaces before the value. Confirmed
	// shipping completely unredacted in a real Windows agent bundle - every
	// systeminfo.exe dump has this exact field pair, so this is a recurring,
	// high-frequency gap, not a one-off. Redacting EVERY manufacturer value
	// (including "Microsoft Corporation"/"VMware, Inc.") is an accepted,
	// deliberate tradeoff: those are public vendor names, not customer PII,
	// but there's no reliable way to distinguish "public vendor" from "the
	// actual customer" by shape alone, and under-redacting the customer's
	// own name/company is the far worse failure mode.
	// [ \t\r]* (not just [ \t]*) before the end anchors: these files commonly
	// have Windows CRLF line endings, and Go's "." matches \r (it only
	// excludes \n) - without \r in the trim class, a trailing \r before each
	// \n gets pulled into the captured value, splitting what's really one
	// name into two near-duplicate dictionary entries (e.g. "Acme Corp" and
	// "Acme Corp\r").
	windowsSysinfoNameFieldRegex = regexp.MustCompile(`(?im)^[ \t]*((?:OS |System )?Manufacturer|Registered Owner|Registered Organization)[ \t\r]*:[ \t\r]*(.+?)[ \t\r]*$`)

	// Windows Installer event log lines pack multiple "Label: value."
	// fields into ONE sentence (e.g. "...Product Language: 1033.
	// Manufacturer: Acme Corp. Reconfiguration success..."), so
	// windowsSysinfoNameFieldRegex's line-start anchor can't reach this -
	// confirmed leaving the same real customer name unredacted here too, in
	// a second file from the same bundle. Captures up to the next period
	// rather than end-of-line, matching that one-sentence-per-field shape.
	windowsInstallerManufacturerRegex = regexp.MustCompile(`\bManufacturer:\s*([^.\n]+)\.`)

	// Short, structured hostname fields - a value immediately following a
	// known hostname-ish key (hostname=, host:, computer_name, node_name,
	// fqdn, agent.hostname) is redacted regardless of length, since the key
	// context itself is strong evidence the value identifies a real host -
	// unlike a bare short word floating in free text, which the generic
	// hostSimpleRegex pass below deliberately leaves alone (see the len(s) <
	// 10 guard there) to avoid false-positiving on ordinary short words.
	hostnameKVRegex = regexp.MustCompile(`(?i)\b(hostname|host|computer[_-]?name|node[_-]?name|fqdn|agent\.hostname)"?\s*[:=]\s*"?([a-zA-Z0-9][a-zA-Z0-9._-]{1,30})\b`)
)

// hostnameKVExcludedValues lists common non-identifying values that
// legitimately follow a hostname-ish key (hostname=localhost, host=unknown,
// etc.) - redacting these would just be placeholder noise, not a real leak.
var hostnameKVExcludedValues = map[string]bool{
	"localhost": true, "unknown": true, "null": true, "none": true,
	"true": true, "false": true, "n/a": true, "na": true,
}

// Mapper
type Mapper struct {
	ipv4    map[string]string
	ipv6    map[string]string
	host    map[string]string
	email   map[string]string
	token   map[string]string
	name    map[string]string
	counts  map[string]int
	skipped map[string]int

	// allowUnscanned controls what happens to a file/nested archive that
	// couldn't be scanned for sensitive data (see recordSkipped and
	// recordNestedFailed): by default (false) it is removed entirely from
	// the anonymized output, since a support-report anonymizer shipping
	// unscanned content unmodified defeats the point of running it. Passing
	// --allow-unscanned sets this true and restores the old behavior of
	// keeping it, unmodified, for cases where the caller specifically wants
	// best-effort completeness over that guarantee.
	allowUnscanned bool

	// run stats, purely for operator-facing logging - not part of the
	// redaction logic itself
	filesScanned   int
	nestedOK       int
	nestedFailed   map[string]int // by extension, mirrors skipped
	skippedRemoved int            // subset of skipped files actually removed (allowUnscanned false)
	nestedRemoved  int            // subset of failed nested archives actually removed (allowUnscanned false)
	dbRemoved      int
}

func NewMapper(allowUnscanned bool) *Mapper {
	return &Mapper{
		ipv4:           make(map[string]string),
		ipv6:           make(map[string]string),
		host:           make(map[string]string),
		email:          make(map[string]string),
		token:          make(map[string]string),
		name:           make(map[string]string),
		counts:         make(map[string]int),
		skipped:        make(map[string]int),
		nestedFailed:   make(map[string]int),
		allowUnscanned: allowUnscanned,
	}
}

// recordSkipped tracks a file that could not be scanned for sensitive data
// because it isn't valid UTF-8 text and isn't a recognized/extractable
// archive format (e.g. a .msg or .pdf attachment). By default it is then
// removed entirely from the anonymized output (see the call site in
// anonymizeTree) rather than shipped unmodified, since its content might
// still carry unredacted customer data; --allow-unscanned keeps the old
// "leave it untouched" behavior instead. Tallied here (by extension) either
// way, to warn the caller what happened to it.
func (m *Mapper) recordSkipped(path string) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		ext = "(no extension)"
	}
	m.skipped[ext]++
	if !m.allowUnscanned {
		m.skippedRemoved++
	}
}

// recordNestedFailed tracks a nested archive (e.g. a corrupt, encrypted, or
// unsupported-codec .gz inside a .tar bundle) whose extraction/repack
// failed. Same removed-by-default/--allow-unscanned-to-keep behavior as
// recordSkipped, but the cause is different (a nested archive we couldn't
// open, vs. a leaf file we couldn't decode as text) so it's tracked and
// reported separately for troubleshooting.
func (m *Mapper) recordNestedFailed(path string) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		ext = "(no extension)"
	}
	m.nestedFailed[ext]++
	if !m.allowUnscanned {
		m.nestedRemoved++
	}
}

// recordDBRemoved tracks a .db file removed entirely from the anonymized
// output (see the removal site in anonymizeTree for why: unlike plain-text
// files, redacting matched values in place risks corrupting a SQLite
// database's fixed internal page offsets, since placeholder tokens aren't
// the same byte length as the values they replace).
func (m *Mapper) recordDBRemoved() {
	m.dbRemoved++
}

func (m *Mapper) get(value, prefix string, store map[string]string) string {
	if v, ok := store[value]; ok {
		return v
	}
	m.counts[prefix]++
	id := fmt.Sprintf("%s_%06d", prefix, m.counts[prefix])
	store[value] = id
	return id
}

// replaceValueGroup replaces only the captured submatch at groupIdx within each
// match of re, leaving the rest of the match (e.g. a surrounding JSON key) intact.
func (m *Mapper) replaceValueGroup(content string, re *regexp.Regexp, groupIdx int, prefix string, store map[string]string) string {
	return re.ReplaceAllStringFunc(content, func(match string) string {
		sub := re.FindStringSubmatch(match)
		if len(sub) <= groupIdx || sub[groupIdx] == "" {
			return match
		}
		placeholder := m.get(sub[groupIdx], prefix, store)
		return strings.Replace(match, sub[groupIdx], placeholder, 1)
	})
}

// replaceHostnameKV redacts the value half of a hostname-ish key=value/key:
// value pair (see hostnameKVRegex) regardless of length, skipping only
// values with no identifying content (hostnameKVExcludedValues) or that are
// purely numeric (a port number, a numeric ID, etc. - not a hostname).
func (m *Mapper) replaceHostnameKV(content string) string {
	return hostnameKVRegex.ReplaceAllStringFunc(content, func(match string) string {
		sub := hostnameKVRegex.FindStringSubmatch(match)
		if len(sub) <= 2 || sub[2] == "" {
			return match
		}
		v := sub[2]
		if isNumeric(v) || hostnameKVExcludedValues[strings.ToLower(v)] {
			return match
		}
		placeholder := m.get(v, "HOST", m.host)
		return strings.Replace(match, v, placeholder, 1)
	})
}

// Heuristics
func looksLikeTime(s string) bool { return timeRegex.MatchString(s) }
func looksLikeDate(s string) bool { return isoDateRegex.MatchString(s) }
func isNumeric(s string) bool     { return numericRegex.MatchString(s) }
func looksLikeHash(s string) bool { return hashRegex.MatchString(s) }
func looksLikeInternalName(s string) bool {
	return camelCaseRegex.MatchString(s)
}
func startsValid(s string) bool {
	return startValidReg.MatchString(s)
}

func looksLikeUUID(s string) bool {
	return uuidRegex.MatchString(s) && strings.Count(s, "-") >= 2
}

func looksLikeTitleCaseWord(s string) bool {
	return titleCaseWordRegex.MatchString(s)
}

func looksLikePascalCaseCompound(s string) bool {
	return pascalCaseCompoundRegex.MatchString(s)
}

func looksLikeAcronymSuffixedWord(s string) bool {
	return acronymSuffixedWordRegex.MatchString(s)
}

func looksLikeTimestampedArtifact(s string) bool {
	return timestampedArtifactRegex.MatchString(s)
}

func looksLikeKebabWord(s string) bool {
	return kebabWordRegex.MatchString(s)
}

func looksLikeGitDescribeSuffix(s string) bool {
	return gitDescribeSuffixRegex.MatchString(s)
}

// dockerBuiltinChains is Docker's own fixed set of iptables/nftables chain
// names it creates on every install (moby/libnetwork's firewall setup) -
// never customer-specific, never renamed. Tightening
// titleCaseHyphenatedRegex (see there) to require real Header-Case instead
// of accepting any-case-after-the-first-letter stopped incidentally
// excluding these as a side effect, so they need an explicit check now -
// confirmed appearing over firewall dumps in real bundle data.
var dockerBuiltinChains = map[string]bool{
	"DOCKER": true, "DOCKER-USER": true, "DOCKER-BRIDGE": true,
	"DOCKER-FORWARD": true, "DOCKER-INGRESS": true,
	"DOCKER-ISOLATION-STAGE-1": true, "DOCKER-ISOLATION-STAGE-2": true,
}

// looksLikeFirewallChainName reports whether s is a known, fixed
// firewall/container chain name rather than a hostname: Docker's own
// built-in chains (see dockerBuiltinChains), any chain starting with "ILO-"
// (this tool's own product prefix for its iptables/nftables chains - never
// a customer hostname by definition), or "ALL-UNNAMED" (a reserved Java
// module-system name - `--add-opens java.base/...=ALL-UNNAMED` - not
// firewall-related but the same all-caps-hyphenated shape and the same fix
// exposed it the same way).
func looksLikeFirewallChainName(s string) bool {
	return dockerBuiltinChains[s] || strings.HasPrefix(s, "ILO-") || s == "ALL-UNNAMED"
}

// kubectlColumnHeaders is `kubectl get`'s own fixed table column headers
// (pods/services/deployments/nodes/etc. all show up in a "kubectl get all"
// or similar dump pasted into a support bundle) - same all-caps-hyphenated
// shape as a multi-segment hostname, same fix exposed them. Single-word
// headers ("NAME", "TYPE", "STATUS", "AGE", "READY", "AVAILABLE") don't need
// listing here - they're already caught by the generic bare-all-caps-word
// guard (looksLikeAllCapsLabel); only hyphenated ones need an explicit
// entry.
var kubectlColumnHeaders = map[string]bool{
	"CLUSTER-IP": true, "EXTERNAL-IP": true, "INTERNAL-IP": true,
	"UP-TO-DATE": true, "NODE-SELECTOR": true, "OS-IMAGE": true,
	"KERNEL-VERSION": true, "CONTAINER-RUNTIME": true, "LAST-SCHEDULE": true,
}

func looksLikeKubectlColumnHeader(s string) bool {
	return kubectlColumnHeaders[s]
}

func looksLikeContainerID(s string) bool {
	return strings.Contains(s, ".scope") || longHexRegex.MatchString(s)
}

func looksLikeFilename(s string) bool {
	exts := []string{
		".log", ".conf", ".sh", ".json", ".xml", ".yaml", ".yml",
		".sock", ".service", ".target", ".mount", ".db", ".jar",
		".crt", ".key", ".nft", ".ipt", ".pid", ".so", ".ini",
		".page", ".swappiness",

		// extended list
		".gz", ".journal", ".tmpl", ".slice",
		".properties", ".socket", ".default",
		".pem", ".statd", ".py", ".timer",
		".que", ".policy",

		// plain report/output files
		".txt", ".csv", ".out", ".dump", ".diag", ".report",

		// compiled web console assets (webpack chunk names, source maps,
		// fonts) - these are vendor frontend files, not hostnames, even
		// when just referenced by name inside other files.
		".js", ".mjs", ".css", ".map", ".html",
		".woff", ".woff2", ".ttf", ".eot", ".otf", ".ico", ".svg",
	}

	for _, ext := range exts {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return numberFileRegex.MatchString(s)
}

// sysctlPrefixes covers both Linux (net./kernel./fs.) and macOS sysctl MIB
// namespaces. macOS diagnostic dumps (sysctl -a output, common in VEN agent
// reports) are dominated by kern./vm./hw./vfs./debug./security./machdep.
// entries like "kern.osversion" or "hw.memsize" - none of these matched the
// original Linux-only prefix list, so hundreds of sysctl names per report
// were being mistaken for hostnames.
var sysctlPrefixes = []string{
	"net.", "kernel.", "fs.",
	"kern.", "vm.", "hw.", "vfs.", "debug.", "security.",
	"machdep.", "kperf.", "ktrace.", "sysctl.", "user.",
}

func looksLikeSysctl(s string) bool {
	for _, p := range sysctlPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// titleCaseHyphenatedRegex matches Header-Case hyphenated words (each
// dash-separated segment capitalized with the REST of the segment
// lowercase, e.g. "Content-Type", "X-Frame-Options", "Cache-Control") - the
// canonical shape of HTTP header field names, and a shape real hostnames
// essentially never take (hostnames are conventionally all-lowercase or
// all-uppercase, not Each-Word-Capitalized). The rest of each segment is
// deliberately restricted to "[a-z]*" rather than "[a-zA-Z]*": the looser
// form also matches all-uppercase hyphenated hostnames like
// "SITE-A-PROD-XYZ12" (each segment still "starts with a capital, followed by
// letters"), which real Header-Case never produces - confirmed leaving a
// real production hostname of exactly that shape completely unredacted.
var titleCaseHyphenatedRegex = regexp.MustCompile(`^[A-Z][a-z]*(-[A-Z][a-z]*)+$`)

func looksLikeHeaderCaseWord(s string) bool {
	return titleCaseHyphenatedRegex.MatchString(s)
}

// javaPropertyRegex matches the lowercase dotted-identifier shape of a Java
// -D system property once the leading "D" is stripped (catalina.home,
// java.awt.headless). Real hostnames starting with "D" almost always mix in
// a digit, uppercase letter, or hyphen somewhere (DC001.corp.com,
// DB-prod01.corp.com) - requiring the rest to be pure lowercase words joined
// by dots avoids rejecting those while still catching genuine -D flags.
var javaPropertyRegex = regexp.MustCompile(`^[a-z]+(\.[a-z]+)+$`)

func looksLikeJavaProperty(s string) bool {
	if !strings.HasPrefix(s, "D") || len(s) < 2 {
		return false
	}
	return javaPropertyRegex.MatchString(s[1:])
}

func looksRandom(s string) bool {
	digits := 0
	upper := 0
	lower := 0
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lower++
		}
	}

	hyphenated := strings.Contains(s, "-") || strings.Contains(s, ".")

	// Hyphenated/dotted tokens with at least one lowercase letter look like
	// conventional hostnames (us-ashburn-1, prod-fra-eu3) and are exempted
	// here regardless of length or digit density.
	if hyphenated && lower > 0 {
		return false
	}

	// A hyphenated/dotted token with digits/uppercase but NO lowercase at
	// all (trace IDs, cache keys, GUID-like identifiers split across
	// dashes - common in HAR request/response bodies) is not a plausible
	// hostname once it has more than one dash-delimited segment: real
	// uppercase host conventions (e.g. default Windows names like
	// "WIN-XXXXXXXXXXX") are effectively always a single prefix plus one
	// suffix segment, never 3+.
	//
	// The digits > 0 requirement was added after this rule was found
	// blocking real production hostnames of exactly this shape (e.g.
	// "SITE-A-PROD-XYZ12", 4 segments, no lowercase, no digits - confirmed
	// via an actual Ollama-flagged miss): a genuinely random/high-entropy
	// token (hex/base36 trace ID, GUID fragment) draws from an alphabet
	// that's mostly digits and is all but certain to include at least one
	// across 2+ segments, whereas a real multi-segment ALL-CAPS hostname
	// built from short words/abbreviations often has none at all. This
	// alone also let through iptables/nftables/Docker's own fixed
	// chain-name vocabulary (DOCKER-USER, ILO-FILTER-INPUT,
	// ILO-MANGLE-POSTROUTING, ALL-UNNAMED, etc. - those have no digits
	// either) - now caught separately and reliably by
	// looksLikeFirewallChainName (see hostSimpleRegex below) regardless of
	// digit count, so it's safe to require digits > 0 here without
	// reopening that regression.
	if hyphenated && lower == 0 && digits > 0 && strings.Count(s, "-") >= 2 {
		return true
	}

	if len(s) < 20 {
		return false
	}
	if hyphenated {
		return false
	}

	// Base64-ish/hash-ish tokens (webpack content hashes, encoded IDs,
	// etc.) mix upper/lower/digit characters far more densely than any
	// real hostname label - a bare 20+ char run with no separators and a
	// three-way mix of character classes is never a hostname.
	return digits > 3 || upper > len(s)/3 || (digits > 0 && upper > 0 && lower > 0)
}

// New targeted filters
func isCrio(s string) bool {
	return strings.HasPrefix(s, "crio-") ||
		strings.HasPrefix(s, "crio-conmon-")
}

func isSystemd(s string) bool {
	return strings.HasSuffix(s, ".slice") ||
		strings.HasSuffix(s, ".scope") ||
		strings.Contains(s, "kubepods")
}

func looksLikeMetric(s string) bool {
	return strings.HasPrefix(s, "TCP") ||
		strings.HasPrefix(s, "In") ||
		strings.HasPrefix(s, "Out")
}

// jsGlobalNamespaces are well-known JavaScript/browser global object names.
// A leading label matching one of these makes the rest of the match almost
// certainly a property/method access chain from minified frontend source
// (e.g. "console.error", "JSON.parse", "Object.assign"), not a hostname.
// "console" and "self" are deliberately excluded here despite being real JS
// globals: both are common real hostname labels in practice ("console.
// illum.io", "console.aws.amazon.com", "self.events.data.microsoft.com" -
// all confirmed in real support case data) and the collision risk outweighs
// their value as a JS-chain signal.
var jsGlobalNamespaces = map[string]bool{
	"window": true, "document": true, "navigator": true,
	"location": true, "history": true, "localStorage": true, "sessionStorage": true,
	"JSON": true, "Math": true, "Object": true, "Array": true, "String": true,
	"Number": true, "Boolean": true, "Symbol": true, "Promise": true, "Error": true,
	"Reflect": true, "Map": true, "Set": true, "WeakMap": true, "WeakSet": true,
	"RegExp": true, "Function": true, "Buffer": true, "Uint8Array": true,
	"ArrayBuffer": true, "Date": true, "globalThis": true,
}

func looksLikeJSGlobalAccess(s string) bool {
	first, _, ok := strings.Cut(s, ".")
	return ok && jsGlobalNamespaces[first]
}

// looksLikeDottedIdentifierChain rejects dotted strings whose leading labels
// have the shape of a JS property-access chain ("e.data.workload.href") or
// an i18n message key ("Common.Active", "Antman.Workloads.CSVEmpty") rather
// than DNS hostname labels: a bare one/two-letter minified variable name, or
// a TitleCase/camelCase word. The final label is left unchecked since real
// TLDs are legitimately short and lowercase (e.g. ".io", ".co").
func looksLikeDottedIdentifierChain(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts[:len(parts)-1] {
		if p == "" {
			continue
		}
		// Only a single-letter label (the classic minifier variable: "e",
		// "t", "n", or its uppercase equivalent "V", "N", "U" seen in real
		// PCE web console HAR data) is treated as a JS-chain signal here.
		// Two-letter lowercase labels are far too common as real region/
		// country subdomain codes (eu., us., uk., ap.) in enterprise
		// domains to safely reject, and multi-letter TitleCase/camelCase
		// labels are dropped entirely - confirmed via real support case
		// data to collide with genuine mixed-case enterprise hostnames
		// (e.g. "avantgardCitrixq20.corp.com", "InBoreappprd01.corp.com")
		// far too often to use as a signal here. A single letter has no
		// such collision risk regardless of case - no real DNS label is
		// ever exactly one character.
		if len(p) == 1 && alphaRegex.MatchString(p) {
			return true
		}
	}
	return false
}

// pascalCaseLabelRegex matches a single dot-separated label with the shape
// of a PascalCase word (starts uppercase, rest alphanumeric, no digits-only
// prefix requirement) - e.g. "StoreUtils", "Common", "Rules".
var pascalCaseLabelRegex = regexp.MustCompile(`^[A-Z][a-zA-Z0-9]*$`)

// looksLikePascalCaseDottedChain rejects dotted strings where every label -
// including the last, unlike looksLikeDottedIdentifierChain above - is
// individually PascalCase-shaped: "StoreUtils.Common.Rules",
// "EventUtils.UserLogin", "Asgard.Insights.ExternalDataTransfer". This is
// the i18n message-key/namespaced-constant convention used throughout a
// minified PCE web console bundle (confirmed in real HAR data from
// console.illum.io), not a hostname shape - real hostnames essentially
// never have EVERY label capitalized, since the trailing label is always a
// real (lowercase) TLD or corporate domain suffix. This is deliberately
// narrower than rejecting any TitleCase-containing dotted string: the two
// real enterprise hostnames documented above ("avantgardCitrixq20.corp.com",
// "InBoreappprd01.corp.com") both have a lowercase trailing label ("corp",
// "com") and so are NOT all-PascalCase - they remain correctly redacted.
func looksLikePascalCaseDottedChain(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if !pascalCaseLabelRegex.MatchString(p) {
			return false
		}
	}
	return true
}

// hostnameContextKeyLiterals is the same closed set of key names
// hostnameKVRegex recognizes as hostname-ish context (see there). If one of
// these literal key names shows up as a dotted/hyphenated identifier
// elsewhere in the text - e.g. "agent.hostname" as a JSON key, appearing
// right next to the value hostnameKVRegex already redacted - it must not
// itself be treated as a hostname value.
var hostnameContextKeyLiterals = map[string]bool{
	"hostname": true, "host": true,
	"computer_name": true, "computer-name": true,
	"node_name": true, "node-name": true,
	"fqdn": true, "agent.hostname": true,
}

func looksLikeHostnameContextKey(s string) bool {
	return hostnameContextKeyLiterals[strings.ToLower(s)]
}

// commonTLDs is an ALLOWLIST of real top-level domains/public suffixes: a
// dotted string is only treated as a hostname if its final label is in
// here. This is the general-purpose fix for reverse-domain-notation
// software/package identifiers (Java packages like "java.base"/
// "jdk.internal", container runtime namespaces like "io.containerd.runc",
// Kubernetes API groups like "daemonset.apps", Azure DevOps predefined
// variables like "com.azure.dev.image.build.buildnumber", macOS extended
// attribute names like "com.apple.provenance") that are dotted, lowercase,
// and otherwise indistinguishable in SHAPE from a real FQDN - confirmed all
// appearing as false positives in real bundle data, each requiring its own
// one-off exclusion (see e.g. looksLikeJavaProperty, looksLikeSysctl)
// before this existed. None of those namespaces end in a label that's
// actually a registered TLD, so gating on TLD membership closes the whole
// class at once instead of chasing it prefix by prefix.
//
// Deliberately NOT exhaustive (real IANA TLD lists run to 1000+ entries,
// most never seen in practice). "corp", "lan", and "intranet" ARE included
// below - confirmed via a real customer's actual internal domain (shaped
// like "sitename.company.corp") shipping completely unredacted before this,
// with no observed collision in real bundle data.
//
// "local" and "internal" are still deliberately EXCLUDED despite being real
// in many enterprise DNS setups (e.g. AWS EC2's "ip-10-0-1-5.ec2.internal"):
// both collide with real, common non-hostname dotted identifiers seen in
// this exact class of Windows support bundle - "jdk.internal" (a real JDK
// module) and, confirmed in a real msinfo32 "loaded modules" dump,
// "microsoft.aspnetcore.cryptography.internal" and
// "system.transactions.local" (real .NET assembly/module names, logged
// lowercase). There's no shape-based way to tell those apart from a real
// "X.internal"/"X.local" hostname, so a hostname ending in either currently
// won't be redacted via this FQDN pass - a known, deliberate gap, not an
// oversight. Expected to grow/change over time as real gaps/false-positives
// turn up in practice, same as dockerBuiltinChains.
var commonTLDs = map[string]bool{
	// Common generic TLDs
	"com": true, "org": true, "net": true, "edu": true, "gov": true,
	"mil": true, "int": true, "info": true, "biz": true, "name": true,
	"pro": true, "coop": true, "museum": true, "jobs": true, "mobi": true,
	"travel": true, "asia": true, "xxx": true,
	// Common newer/tech-oriented gTLDs, frequent in real support bundles
	"io": true, "ai": true, "co": true, "me": true, "tv": true,
	"dev": true, "app": true, "cloud": true, "tech": true, "xyz": true,
	"site": true, "online": true, "store": true, "blog": true, "wiki": true,
	"click": true, "link": true, "run": true, "page": true, "live": true,
	"world": true, "top": true, "one": true, "cc": true, "ly": true,
	"gg": true, "sh": true,
	// Common country-code TLDs (ccTLDs) likely across a global customer base
	"us": true, "uk": true, "ca": true, "au": true, "de": true, "fr": true,
	"jp": true, "cn": true, "in": true, "br": true, "ru": true, "nl": true,
	"se": true, "no": true, "fi": true, "dk": true, "es": true, "it": true,
	"ch": true, "at": true, "be": true, "pl": true, "cz": true, "ie": true,
	"nz": true, "sg": true, "hk": true, "tw": true, "kr": true, "mx": true,
	"za": true, "il": true, "ae": true, "sa": true, "tr": true, "gr": true,
	"pt": true, "hu": true, "ro": true, "bg": true, "hr": true, "sk": true,
	"si": true, "lt": true, "lv": true, "ee": true, "is": true, "lu": true,
	"mt": true, "cy": true, "id": true, "my": true, "th": true, "vn": true,
	"ph": true, "ar": true, "cl": true, "pe": true, "uy": true, "ec": true,
	"ve": true, "pa": true, "cr": true, "do": true, "gt": true,
	// Common enterprise-internal suffixes (see the "local"/"internal"
	// exclusion note above for why those two specifically are held back)
	"corp": true, "lan": true, "intranet": true,
}

func hasRecognizedTLD(s string) bool {
	tld := s
	if i := strings.LastIndex(s, "."); i >= 0 {
		tld = s[i+1:]
	}
	return commonTLDs[strings.ToLower(tld)]
}

// looksLikeNonHostnameFQDN runs the full set of "don't redact this" guards
// shared by both dotted-hostname passes in Replace() (the main hostFQDNRegex
// pass and the underscore-adjacent pass) - factored out so both apply
// exactly the same checks rather than risking the two passes drifting out
// of sync over time.
func looksLikeNonHostnameFQDN(s string) bool {
	// looksLikeMetric is intentionally not applied here: it targets
	// undotted SNMP/network counter names (InOctets, TCPRetransSegs) that
	// never match hostFQDNRegex in the first place (it requires a dot), so
	// here it would only ever misfire on real hostnames that happen to
	// start with "In"/"Out"/"TCP" (e.g. InBoreappprd01.corp.com).
	if ansiRegex.MatchString(s) || isCrio(s) || isSystemd(s) {
		return true
	}
	if looksLikeFilename(s) || looksLikeTime(s) || looksLikeDate(s) {
		return true
	}
	if looksLikeSysctl(s) || looksLikeJavaProperty(s) || looksLikeInternalName(s) {
		return true
	}
	if looksLikeJSGlobalAccess(s) || looksLikeDottedIdentifierChain(s) || looksLikePascalCaseDottedChain(s) {
		return true
	}
	if looksLikeHostnameContextKey(s) {
		return true
	}
	if !hasRecognizedTLD(s) {
		return true
	}
	return false
}

// allCapsLabelRegex matches a bare all-uppercase-letters word (e.g. "VAR",
// "ENV") - the shape of a constant/environment-variable name fragment, not
// a real DNS label (hostnames are conventionally lowercase or mixed-case,
// never a bare all-caps word).
var allCapsLabelRegex = regexp.MustCompile(`^[A-Z]{2,}$`)

// looksLikeAllCapsLabel reports whether the first dot-separated label of s
// is a bare all-caps word, e.g. "VAR" in "VAR.example" - a signal specific
// to the underscoreHostnameRegex pass, where an immediately-preceding
// underscore plus an all-caps leading label (as in "MY_ENV_VAR.example")
// is a strong sign of a constant/env-var name, not a hostname. Not folded
// into looksLikeNonHostnameFQDN above since the main FQDN pass has no
// underscore context to trigger on in the first place.
func looksLikeAllCapsLabel(s string) bool {
	first, _, _ := strings.Cut(s, ".")
	return allCapsLabelRegex.MatchString(first)
}

// webAssetExtensions lists compiled frontend asset file types that ship as
// part of the PCE's own web console (webpack JS/CSS bundles, source maps,
// fonts, icons). These are vendor code - identical across every install of
// a given PCE version - and never contain customer-specific data, so their
// contents are skipped entirely rather than run through the hostname/IP/etc.
// regexes, which otherwise misfire heavily on minified JS property chains,
// CSS custom properties, and i18n message keys embedded in that text.
var webAssetExtensions = []string{
	".js", ".js.map", ".mjs",
	".css", ".css.map",
	".map",
	".woff", ".woff2", ".ttf", ".eot", ".otf",
}

func isWebAssetFile(path string) bool {
	for _, ext := range webAssetExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// maxInvalidUTF8Ratio bounds how much of a file's bytes may be part of
// invalid UTF-8 sequences while still being treated as scannable text.
// Real binary formats (SQLite pages, images, compiled binaries) run well
// above this in practice (~15-20%+ invalid in samples seen); a plain-text
// log file with a single embedded non-UTF-8 byte run (e.g. a Shift-JIS
// string logged inline in an otherwise-ASCII line) sits far below it.
const maxInvalidUTF8Ratio = 0.05

// isMostlyText reports whether data is predominantly valid UTF-8, tolerating
// a small fraction of invalid byte sequences rather than requiring the
// entire file to be valid. Rejecting a file outright over a single bad byte
// (utf8.Valid's all-or-nothing behavior) means every real hostname/IP/email
// elsewhere in an otherwise plain-text file goes unredacted - Go's regexp
// matches ASCII patterns correctly around invalid UTF-8 runs and leaves
// them untouched in the output, so partial validity is safe to scan.
func isMostlyText(data []byte) bool {
	if len(data) == 0 {
		return true
	}

	invalid := 0
	runes := 0
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		runes++
		if r == utf8.RuneError && size == 1 {
			invalid++
		}
		i += size
	}

	return float64(invalid)/float64(runes) <= maxInvalidUTF8Ratio
}

// Replace logic
func (m *Mapper) Replace(content string) string {

	content = ipv4Regex.ReplaceAllStringFunc(content, func(s string) string {
		return m.get(s, "IPV4", m.ipv4)
	})

	content = ipv6Regex.ReplaceAllStringFunc(content, func(s string) string {
		if looksLikeTime(s) {
			return s
		}
		return m.get(s, "IPV6", m.ipv6)
	})

	content = emailRegex.ReplaceAllStringFunc(content, func(s string) string {
		return m.get(s, "EMAIL", m.email)
	})

	// Tokens / API keys / secrets (run before hostname passes so token bodies
	// aren't partially consumed/skipped by the hostname heuristics first)
	content = jwtRegex.ReplaceAllStringFunc(content, func(s string) string {
		return m.get(s, "TOKEN", m.token)
	})
	content = awsAccessKeyRegex.ReplaceAllStringFunc(content, func(s string) string {
		return m.get(s, "TOKEN", m.token)
	})
	content = githubTokenRegex.ReplaceAllStringFunc(content, func(s string) string {
		return m.get(s, "TOKEN", m.token)
	})
	content = slackTokenRegex.ReplaceAllStringFunc(content, func(s string) string {
		return m.get(s, "TOKEN", m.token)
	})
	content = m.replaceValueGroup(content, bearerAuthRegex, 2, "TOKEN", m.token)
	content = m.replaceValueGroup(content, basicAuthRegex, 2, "TOKEN", m.token)
	content = m.replaceValueGroup(content, secretKVRegex, 2, "TOKEN", m.token)
	content = m.replaceValueGroup(content, secretEqualsKVRegex, 2, "TOKEN", m.token)
	content = m.replaceValueGroup(content, cookieHeaderRegex, 2, "TOKEN", m.token)
	content = pemPrivateKeyRegex.ReplaceAllStringFunc(content, func(s string) string {
		return m.get(s, "TOKEN", m.token)
	})

	// Personal names
	content = m.replaceValueGroup(content, nameKVRegex, 2, "NAME", m.name)
	content = m.replaceValueGroup(content, windowsSysinfoNameFieldRegex, 2, "NAME", m.name)
	content = m.replaceValueGroup(content, windowsInstallerManufacturerRegex, 1, "NAME", m.name)

	// Short, structured hostnames (see hostnameKVRegex) - run before the
	// generic FQDN/simple-hostname passes below so a short value already
	// redacted here doesn't need to also satisfy their longer-only/
	// heuristic gates.
	content = m.replaceHostnameKV(content)

	// A real hostname immediately preceded by an underscore with NO
	// intervening "-"/"." (e.g. Illumio's own "FQDN_<hostname>" CSV export
	// convention, or a unix socket path like "sbus-dp_ads.company.com")
	// can never be reached by hostFQDNRegex below at all: Go's \b is
	// defined over \w (which includes "_"), so there is no word boundary
	// between the underscore and the hostname's true first letter, and the
	// char class stops at "_" (not part of it) so the match can't span
	// across it either - confirmed leaving "ads.company.com" completely
	// unredacted in practice. This pass targets exactly that gap: it
	// matches only the hostname-shaped text following a literal
	// underscore (capturing it separately so the underscore itself and
	// whatever precedes it is left untouched), and runs the same guard
	// chain as the main FQDN pass below, plus an extra check rejecting an
	// ALL-CAPS first label (e.g. "MY_ENV_VAR.example" - a constant/
	// env-var name fragment, not a hostname; real hostname labels are
	// never bare all-uppercase words). Runs BEFORE the main FQDN pass:
	// once that pass has already replaced the trailing portion with a
	// placeholder, the underscore-adjacent text no longer has the shape
	// this pass looks for.
	content = underscoreHostnameRegex.ReplaceAllStringFunc(content, func(match string) string {
		sub := underscoreHostnameRegex.FindStringSubmatch(match)
		if len(sub) <= 1 || sub[1] == "" {
			return match
		}
		s := sub[1]
		if looksLikeAllCapsLabel(s) || looksLikeNonHostnameFQDN(s) {
			return match
		}
		placeholder := m.get(s, "HOST", m.host)
		return strings.Replace(match, s, placeholder, 1)
	})

	// FQDN
	content = hostFQDNRegex.ReplaceAllStringFunc(content, func(s string) string {

		// A leading "-"/"." is stripped (and preserved verbatim in the
		// output) rather than causing the whole match to be skipped - see
		// the underscoreHostnameRegex pass above for the related
		// underscore-adjacent case this doesn't cover.
		leadingChars := ""
		for len(s) > 0 && (s[0] == '-' || s[0] == '.') {
			leadingChars += string(s[0])
			s = s[1:]
		}
		if s == "" {
			return leadingChars
		}

		if looksLikeNonHostnameFQDN(s) {
			return leadingChars + s
		}

		return leadingChars + m.get(s, "HOST", m.host)
	})

	// Simple hostnames
	content = hostSimpleRegex.ReplaceAllStringFunc(content, func(s string) string {

		// See the matching comment in the FQDN branch above: a leading "-"
		// from an underscore-adjacent real hostname (e.g. "foo_-bar-01") is
		// stripped and preserved verbatim rather than rejecting the whole
		// match.
		leadingChars := ""
		for len(s) > 0 && s[0] == '-' {
			leadingChars += string(s[0])
			s = s[1:]
		}

		if len(s) < 10 {
			return leadingChars + s
		}

		if strings.HasPrefix(s, "-") || strings.HasPrefix(s, ".") {
			return leadingChars + s
		}

		if ansiRegex.MatchString(s) ||
			isCrio(s) ||
			isSystemd(s) ||
			looksLikeMetric(s) {
			return leadingChars + s
		}

		if !startsValid(s) ||
			isNumeric(s) ||
			strings.HasPrefix(s, "0x") {
			return leadingChars + s
		}

		if looksRandom(s) ||
			looksLikeUUID(s) ||
			looksLikeContainerID(s) {
			return leadingChars + s
		}

		if !alphaRegex.MatchString(s) {
			return leadingChars + s
		}

		if looksLikeDate(s) || looksLikeTime(s) ||
			looksLikeFilename(s) ||
			looksLikeInternalName(s) ||
			looksLikeTitleCaseWord(s) ||
			looksLikePascalCaseCompound(s) ||
			looksLikeTimestampedArtifact(s) ||
			looksLikeKebabWord(s) ||
			looksLikeHeaderCaseWord(s) ||
			looksLikeGitDescribeSuffix(s) ||
			looksLikeFirewallChainName(s) ||
			looksLikeKubectlColumnHeader(s) ||
			looksLikeAcronymSuffixedWord(s) {
			return leadingChars + s
		}

		if looksLikeSysctl(s) || looksLikeJavaProperty(s) ||
			looksLikeHash(s) ||
			lowerWordRegex.MatchString(s) ||
			looksLikeAllCapsLabel(s) {
			return leadingChars + s
		}

		if looksLikeHostnameContextKey(s) {
			return leadingChars + s
		}

		return leadingChars + m.get(s, "HOST", m.host)
	})

	return content
}

// Execution pipeline
func Execute(input string, allowUnscanned bool) error {
	start := time.Now()
	mapper := NewMapper(allowUnscanned)

	if !isArchive(input) {
		return processSingleFile(input, mapper)
	}

	output, format := deriveOutputName(input)

	info, err := os.Stat(input)
	if err != nil {
		// Surface the real reason (missing file, permission denied, etc.)
		// immediately - silently defaulting to "size=0 bytes" here previously
		// masked a missing/inaccessible input behind a misleading log line
		// that looked identical to a genuinely empty archive.
		return fmt.Errorf("reading input %s: %w", input, err)
	}
	utils.LogInfo(fmt.Sprintf(
		"anonymize-support-report: starting input=%s size=%d bytes format=%s output=%s",
		input, info.Size(), format, output), true)

	tmpDir, err := os.MkdirTemp("", "anon")
	if err != nil {
		return fmt.Errorf("creating scratch directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := extract(input, tmpDir); err != nil {
		return fmt.Errorf("extracting %s: %w", input, err)
	}

	if err := anonymizeTree(tmpDir, mapper); err != nil {
		return fmt.Errorf("scanning extracted contents of %s: %w", input, err)
	}

	if err := createArchive(format, output, tmpDir); err != nil {
		return fmt.Errorf("repacking anonymized archive to %s: %w", output, err)
	}

	warnNestedFailed(mapper)
	warnSkipped(mapper)
	warnDBRemoved(mapper)

	if err := writeMapping(output, mapper); err != nil {
		utils.LogWarning(fmt.Sprintf("failed to write mapping file for %s: %v", output, err), true)
	}

	logSummary(mapper, output, time.Since(start))
	return nil
}

// anonymizeTree walks root, anonymizing text file contents in place. Files
// that are themselves recognized archives/compressed files are recursively
// extracted, anonymized, and repacked in place so their contents aren't left
// untouched just because the outer file is binary - with no depth limit:
// an archive nested inside an archive inside an archive (however many
// levels) is always followed all the way down, since a depth cap would mean
// customer data past that point ships unscanned.
func anonymizeTree(root string, mapper *Mapper) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		// .db files (SQLite databases) are removed entirely rather than
		// redacted in place or copied through unmodified. They frequently
		// carry embedded plaintext IPs/emails/hostnames that isMostlyText
		// would otherwise cause to ship completely unredacted (the file as
		// a whole reads as binary, so it never reaches mapper.Replace at
		// all) - but redacting matched substrings in place isn't safe
		// either, since SQLite relies on fixed internal page offsets and a
		// placeholder token being a different byte length than the value it
		// replaces risks corrupting the database. Removing the file is the
		// only option that both closes the leak and doesn't risk shipping a
		// corrupted file - the original is still available outside the
		// anonymized archive for anyone who needs to review it directly.
		if strings.EqualFold(filepath.Ext(path), ".db") {
			mapper.recordDBRemoved()
			return os.Remove(path)
		}

		if k, ok := detectArchive(path); ok {
			if err := anonymizeNestedArchive(path, k, mapper); err == nil {
				mapper.nestedOK++
				return nil
			}
			// Extraction/repack of the nested archive failed (corrupt,
			// encrypted, unsupported codec, etc.). By default it must
			// not ride along inside the anonymized bundle unscanned -
			// removed unless --allow-unscanned explicitly keeps it.
			mapper.recordNestedFailed(path)
			if !mapper.allowUnscanned {
				return os.Remove(path)
			}
			return nil
		}

		if isWebAssetFile(path) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if !isMostlyText(data) {
			// Binary format we can't extract text from (e.g. .msg/.pdf). By
			// default it's removed entirely from the anonymized output
			// rather than shipped unmodified, since it could still carry
			// unredacted customer data - --allow-unscanned keeps it as-is.
			mapper.recordSkipped(path)
			if !mapper.allowUnscanned {
				return os.Remove(path)
			}
			return nil
		}

		updated := mapper.Replace(string(data))
		mapper.filesScanned++
		return os.WriteFile(path, []byte(updated), info.Mode())
	})
}

// anonymizeNestedArchive extracts the archive at path into a scratch temp
// dir, recursively anonymizes it, and repacks it back to the same directory
// entry (same name, except 7z/rar which become .zip since neither can be
// re-written in their original format).
func anonymizeNestedArchive(path string, k archiveKind, mapper *Mapper) error {
	nestedDir, err := os.MkdirTemp("", "anon-nested")
	if err != nil {
		return err
	}
	defer os.RemoveAll(nestedDir)

	if err := extract(path, nestedDir); err != nil {
		return err
	}

	if err := anonymizeTree(nestedDir, mapper); err != nil {
		return err
	}

	newPath := filepath.Join(filepath.Dir(path), strings.TrimSuffix(filepath.Base(path), k.suffix)+k.outSuffix)

	if err := createArchive(k.format, newPath, nestedDir); err != nil {
		return err
	}

	if newPath != path {
		return os.Remove(path)
	}
	return nil
}

// createArchive repacks the contents of src into output using the writer for
// the given format.
func createArchive(format, output, src string) error {
	switch format {
	case "zip":
		return createZip(output, src)
	case "cab":
		return createCab(output, src)
	case "tar":
		return createPlainTar(output, src)
	case "tar.gz":
		return createTarGz(output, src)
	case "tar.bz2":
		return createTarBz2(output, src)
	case "tar.xz":
		return createTarXz(output, src)
	case "gz":
		return createSingleGz(output, src)
	case "bz2":
		return createSingleBz2(output, src)
	case "xz":
		return createSingleXz(output, src)
	case "7z", "rar":
		// Neither format has a viable open-source Go writer, so the
		// anonymized contents are repacked as a .zip instead.
		return createZip(output, src)
	}
	return fmt.Errorf("unsupported archive format: %s", format)
}

// archiveKind maps an input suffix to the internal format identifier used for
// extraction/creation dispatch, and the suffix to use for the output file name.
type archiveKind struct {
	suffix    string
	format    string
	outSuffix string
}

// Ordered so compound suffixes (e.g. ".tar.gz") are matched before the
// shorter, single-file suffix they also happen to end with (e.g. ".gz").
var archiveKinds = []archiveKind{
	{".tar.gz", "tar.gz", ".tar.gz"},
	{".tgz", "tar.gz", ".tgz"},
	{".tar.bz2", "tar.bz2", ".tar.bz2"},
	{".tbz2", "tar.bz2", ".tbz2"},
	{".tar.xz", "tar.xz", ".tar.xz"},
	{".txz", "tar.xz", ".txz"},
	{".tar", "tar", ".tar"},
	{".zip", "zip", ".zip"},
	// Office Open XML formats (.docx/.xlsx/.pptx and their macro-enabled
	// variants) are zip containers under the hood - text content (cell
	// values, document body, slide text) lives in plain XML parts inside,
	// so they need the same extract/anonymize/repack treatment as any
	// other archive rather than being left as opaque binary and copied
	// through untouched.
	{".docx", "zip", ".docx"},
	{".dotx", "zip", ".dotx"},
	{".xlsx", "zip", ".xlsx"},
	{".xlsm", "zip", ".xlsm"},
	{".pptx", "zip", ".pptx"},
	{".ppsx", "zip", ".ppsx"},
	{".cab", "cab", ".cab"},
	// 7z/rar can't be re-written in their original format, so anonymized
	// output is repacked as .zip.
	{".7z", "7z", ".zip"},
	{".rar", "rar", ".zip"},
	{".gz", "gz", ".gz"},
	{".bz2", "bz2", ".bz2"},
	{".xz", "xz", ".xz"},
}

func detectArchive(input string) (archiveKind, bool) {
	for _, k := range archiveKinds {
		if strings.HasSuffix(input, k.suffix) {
			return k, true
		}
	}
	return archiveKind{}, false
}

// Archive helpers (FULLY RESTORED)
func isArchive(input string) bool {
	_, ok := detectArchive(input)
	return ok
}

func processSingleFile(input string, mapper *Mapper) error {
	start := time.Now()

	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("reading %s: %w", input, err)
	}

	if !isMostlyText(data) {
		return fmt.Errorf("%s is a binary format that can't be scanned for sensitive data - review it manually", input)
	}

	ext := filepath.Ext(input)
	output := strings.TrimSuffix(input, ext) + ".anonymized" + ext

	utils.LogInfo(fmt.Sprintf(
		"anonymize-support-report: starting input=%s size=%d bytes mode=single-file output=%s",
		input, len(data), output), true)

	if isWebAssetFile(input) {
		utils.LogInfo(fmt.Sprintf(
			"anonymize-support-report summary: %s is a web asset file (vendor frontend code), copied through unmodified, duration=%s",
			input, time.Since(start).Round(time.Millisecond)), true)
		return os.WriteFile(output, data, 0644)
	}

	updated := mapper.Replace(string(data))
	mapper.filesScanned++
	if err := os.WriteFile(output, []byte(updated), 0644); err != nil {
		return fmt.Errorf("writing anonymized output to %s: %w", output, err)
	}

	if err := writeMapping(output, mapper); err != nil {
		utils.LogWarning(fmt.Sprintf("failed to write mapping file for %s: %v", output, err), true)
	}

	logSummary(mapper, output, time.Since(start))
	return nil
}

func deriveOutputName(input string) (string, string) {
	k, ok := detectArchive(input)
	if !ok {
		return input + ".anonymized", ""
	}
	base := strings.TrimSuffix(input, k.suffix)
	return base + ".anonymized" + k.outSuffix, k.format
}

// warnSkipped surfaces files that couldn't be scanned for sensitive data
// (opaque binary formats like .msg/.pdf that aren't extractable archives) so
// the caller knows to manually review them rather than assuming everything
// was anonymized.
// formatExtCounts renders a by-extension count map as a sorted, deterministic
// "total, .ext:count, .ext:count, ..." pair for log messages.
func formatExtCounts(counts map[string]int) (total int, breakdown string) {
	exts := make([]string, 0, len(counts))
	for ext := range counts {
		exts = append(exts, ext)
	}
	sort.Strings(exts)

	parts := make([]string, 0, len(exts))
	for _, ext := range exts {
		count := counts[ext]
		total += count
		parts = append(parts, fmt.Sprintf("%s:%d", ext, count))
	}
	return total, strings.Join(parts, ", ")
}

func warnSkipped(m *Mapper) {
	if len(m.skipped) == 0 {
		return
	}
	total, breakdown := formatExtCounts(m.skipped)
	if m.allowUnscanned {
		utils.LogWarning(fmt.Sprintf(
			"%d file(s) could not be scanned for sensitive data (binary formats not supported for text extraction: %s) - "+
				"KEPT unmodified in the anonymized output because --allow-unscanned was set - review these manually",
			total, breakdown), true)
		return
	}
	utils.LogWarning(fmt.Sprintf(
		"%d file(s) could not be scanned for sensitive data (binary formats not supported for text extraction: %s) - "+
			"REMOVED entirely from the anonymized output (not copied through) - review the ORIGINAL file(s) directly if "+
			"their content needs checking, or re-run with --allow-unscanned to keep them in the output unmodified instead",
		total, breakdown), true)
}

// warnDBRemoved reports .db files removed entirely from the anonymized
// output (see the removal site in anonymizeTree for the full reasoning:
// redacting in place risks corrupting SQLite's fixed internal page
// offsets, so removal is the safer option). Unlike warnSkipped, these
// files are NOT present in the anonymized archive at all - review the
// original bundle directly if their content needs checking.
func warnDBRemoved(m *Mapper) {
	if m.dbRemoved == 0 {
		return
	}
	utils.LogWarning(fmt.Sprintf(
		"%d .db file(s) were removed entirely from the anonymized output (not redacted, not included - "+
			"in-place redaction risks corrupting a SQLite database's fixed internal page offsets) - "+
			"review the ORIGINAL .db file(s) directly if their content needs checking",
		m.dbRemoved), true)
}

// warnNestedFailed reports nested archives (e.g. a corrupt or password-
// protected .gz inside a .tar bundle) that couldn't be extracted/repacked
// and so were left untouched as opaque binary - previously this failure was
// completely silent, giving no indication that a whole nested archive's
// contents went unscanned.
func warnNestedFailed(m *Mapper) {
	if len(m.nestedFailed) == 0 {
		return
	}
	total, breakdown := formatExtCounts(m.nestedFailed)
	if m.allowUnscanned {
		utils.LogWarning(fmt.Sprintf(
			"%d nested archive(s) could not be extracted (corrupt, encrypted, or unsupported: %s) - "+
				"KEPT unmodified in the anonymized output because --allow-unscanned was set - their contents are unscanned, review manually",
			total, breakdown), true)
		return
	}
	utils.LogWarning(fmt.Sprintf(
		"%d nested archive(s) could not be extracted (corrupt, encrypted, or unsupported: %s) - "+
			"REMOVED entirely from the anonymized output rather than shipped unscanned - review the ORIGINAL bundle directly if "+
			"their content needs checking, or re-run with --allow-unscanned to keep them in the output unmodified instead",
		total, breakdown), true)
}

// logSummary reports what the run actually did: how many files were scanned
// and redacted per category, how many nested archives were recursed into
// (and how many failed), and where the output landed - replacing the
// previous single "completed" line with enough detail to troubleshoot a run
// without re-running it.
func logSummary(m *Mapper, output string, elapsed time.Duration) {
	utils.LogInfo(fmt.Sprintf(
		"anonymize-support-report summary: duration=%s files_scanned=%d nested_archives_recursed=%d db_files_removed=%d "+
			"unscanned_files_removed=%d unscanned_nested_archives_removed=%d allow_unscanned=%t "+
			"ipv4=%d ipv6=%d host=%d email=%d token=%d name=%d output=%s mapping=%s",
		elapsed.Round(time.Millisecond), m.filesScanned, m.nestedOK, m.dbRemoved,
		m.skippedRemoved, m.nestedRemoved, m.allowUnscanned,
		len(m.ipv4), len(m.ipv6), len(m.host), len(m.email), len(m.token), len(m.name),
		output, output+".mapping.json"), true)
}

func writeMapping(output string, m *Mapper) error {
	file := output + ".mapping.json"

	data := map[string]interface{}{
		"ipv4":  m.ipv4,
		"ipv6":  m.ipv6,
		"host":  m.host,
		"email": m.email,
		"token": m.token,
		"name":  m.name,
	}

	f, err := os.Create(file)
	if err != nil {
		return fmt.Errorf("creating %s: %w", file, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("writing %s: %w", file, err)
	}
	return nil
}

// safeJoin joins name onto dest and rejects the result if it would land
// outside dest (a "zip-slip" archive entry using ".." components, e.g.
// "../../../../etc/cron.d/x", to escape the extraction directory). Archive
// contents come from externally-submitted support bundles, which could in
// principle be maliciously crafted, so entry names can't be trusted as-is.
func safeJoin(dest, name string) (string, error) {
	path := filepath.Join(dest, name)
	cleanDest := filepath.Clean(dest)
	if path != cleanDest && !strings.HasPrefix(path, cleanDest+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry escapes destination directory: %s", name)
	}
	return path, nil
}

func extract(src, dest string) error {
	k, ok := detectArchive(src)
	if !ok {
		return fmt.Errorf("unsupported archive: %s", src)
	}

	switch k.format {
	case "zip":
		return unzip(src, dest)
	case "cab":
		return extractCab(src, dest)
	case "7z":
		return extractSevenZip(src, dest)
	case "rar":
		return extractRar(src, dest)
	case "tar":
		return extractTarFrom(src, dest, func(f *os.File) (io.Reader, error) { return f, nil })
	case "tar.gz":
		return extractTarFrom(src, dest, func(f *os.File) (io.Reader, error) { return gzip.NewReader(f) })
	case "tar.bz2":
		return extractTarFrom(src, dest, func(f *os.File) (io.Reader, error) { return dbzip2.NewReader(f, nil) })
	case "tar.xz":
		return extractTarFrom(src, dest, func(f *os.File) (io.Reader, error) { return xz.NewReader(f) })
	case "gz":
		return extractSingleCompressed(src, dest, k.suffix, func(f *os.File) (io.Reader, error) { return gzip.NewReader(f) })
	case "bz2":
		return extractSingleCompressed(src, dest, k.suffix, func(f *os.File) (io.Reader, error) { return dbzip2.NewReader(f, nil) })
	case "xz":
		return extractSingleCompressed(src, dest, k.suffix, func(f *os.File) (io.Reader, error) { return xz.NewReader(f) })
	}
	return fmt.Errorf("unsupported archive: %s", src)
}

// extractTarFrom opens src, wraps it via decompress (a no-op for plain .tar),
// and extracts the resulting tar stream into dest.
func extractTarFrom(src, dest string, decompress func(*os.File) (io.Reader, error)) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := decompress(f)
	if err != nil {
		return err
	}

	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		path, err := safeJoin(dest, h.Name)
		if err != nil {
			return err
		}

		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}
			out, err := os.Create(path)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, tr)
			out.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// extractSingleCompressed decompresses a single-file archive (.gz/.bz2/.xz
// that isn't a tarball) into dest, preserving the base name minus the
// compression suffix.
func extractSingleCompressed(src, dest, suffix string, decompress func(*os.File) (io.Reader, error)) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := decompress(f)
	if err != nil {
		return err
	}

	name := filepath.Base(strings.TrimSuffix(src, suffix))
	out, err := os.Create(filepath.Join(dest, name))
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, r)
	return err
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		path, err := safeJoin(dest, f.Name)
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			rc.Close()
			return err
		}

		out, err := os.Create(path)
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractCab(src, dest string) error {
	r, err := cabinet.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, cf := range r.Files {
		path, err := safeJoin(dest, cf.Name)
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		rc, err := cf.Open()
		if err != nil {
			return err
		}

		out, err := os.Create(path)
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractSevenZip(src, dest string) error {
	r, err := sevenzip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, sf := range r.File {
		path, err := safeJoin(dest, sf.Name)
		if err != nil {
			return err
		}

		if sf.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		rc, err := sf.Open()
		if err != nil {
			return err
		}

		out, err := os.Create(path)
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractRar(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	rr, err := rardecode.NewReader(f)
	if err != nil {
		return err
	}

	for {
		hdr, err := rr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		path, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}

		if hdr.IsDir {
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		out, err := os.Create(path)
		if err != nil {
			return err
		}

		_, err = io.Copy(out, rr)
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func createCab(output, src string) error {
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	w := cabinet.NewWriter(f)

	err = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		return w.AddPath(filepath.ToSlash(rel), path)
	})
	if err != nil {
		return err
	}

	return w.Close()
}

func createTarGz(output, src string) error {
	f, _ := os.Create(output)
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if info == nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(src, path)

		h, _ := tar.FileInfoHeader(info, "")
		h.Name = rel

		tw.WriteHeader(h)
		data, _ := os.ReadFile(path)
		tw.Write(data)
		return nil
	})
	return nil
}

// writeTarEntries walks src and writes every regular file into tw.
func writeTarEntries(tw *tar.Writer, src string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)

		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
}

func createPlainTar(output, src string) error {
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	if err := writeTarEntries(tw, src); err != nil {
		tw.Close()
		return err
	}
	return tw.Close()
}

func createTarBz2(output, src string) error {
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	bw, err := dbzip2.NewWriter(f, nil)
	if err != nil {
		return err
	}

	tw := tar.NewWriter(bw)
	if err := writeTarEntries(tw, src); err != nil {
		tw.Close()
		bw.Close()
		return err
	}
	if err := tw.Close(); err != nil {
		bw.Close()
		return err
	}
	return bw.Close()
}

func createTarXz(output, src string) error {
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	xw, err := xz.NewWriter(f)
	if err != nil {
		return err
	}

	tw := tar.NewWriter(xw)
	if err := writeTarEntries(tw, src); err != nil {
		tw.Close()
		xw.Close()
		return err
	}
	if err := tw.Close(); err != nil {
		xw.Close()
		return err
	}
	return xw.Close()
}

// singleFileInDir returns the path of the (only) regular file within dir.
func singleFileInDir(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", fmt.Errorf("no file found in %s", dir)
}

func createSingleGz(output, src string) error {
	inPath, err := singleFileInDir(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}

	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	if _, err := gw.Write(data); err != nil {
		gw.Close()
		return err
	}
	return gw.Close()
}

func createSingleBz2(output, src string) error {
	inPath, err := singleFileInDir(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}

	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	bw, err := dbzip2.NewWriter(f, nil)
	if err != nil {
		return err
	}
	if _, err := bw.Write(data); err != nil {
		bw.Close()
		return err
	}
	return bw.Close()
}

func createSingleXz(output, src string) error {
	inPath, err := singleFileInDir(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}

	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	xw, err := xz.NewWriter(f)
	if err != nil {
		return err
	}
	if _, err := xw.Write(data); err != nil {
		xw.Close()
		return err
	}
	return xw.Close()
}

func createZip(output, src string) error {
	f, _ := os.Create(output)
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if info == nil || info.IsDir() {
			return nil
		}

		rel, _ := filepath.Rel(src, path)
		h, _ := zip.FileInfoHeader(info)

		h.Name = filepath.ToSlash(rel)
		w, _ := zw.CreateHeader(h)

		data, _ := os.ReadFile(path)
		w.Write(data)
		return nil
	})
	return nil
}
