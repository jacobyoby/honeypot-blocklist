package validator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	schemaVersion       = "1.0"
	claimDriftTolerance = 0.10
)

var (
	validTiers = map[string]struct{}{
		"credential": {},
		"scanner":    {},
	}
	tierMinimumAttempts = map[string]int64{
		"credential": 50,
		"scanner":    1000,
	}
	requiredMeta = []string{
		"name", "description", "maintainer", "homepage", "contact",
		"inclusion_criteria", "window_days", "count", "count_by_tier",
		"updated", "license",
	}
	requiredEntry = []string{
		"ip", "tier", "bans", "attempts", "first_seen", "last_seen",
		"first_banned", "asn",
	}
	csvColumns = []string{
		"ip", "tier", "bans", "attempts", "first_seen", "last_seen",
		"first_banned", "asn",
	}
	semverPattern     = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	asnPattern        = regexp.MustCompile(`^AS[0-9]+$`)
	measuredAtPattern = regexp.MustCompile(
		`(?is)measured\s+([0-9]{4}-[0-9]{2}-[0-9]{2}).{0,120}?([0-9,]+)-entry feed`,
	)
)

type validationOptions struct {
	displayRoot              string
	allowDocumentationRanges bool
}

type validationState struct {
	fsys       fs.FS
	options    validationOptions
	result     Result
	entries    []map[string]any
	jsonIPs    map[string]struct{}
	csvIPs     map[string]struct{}
	txtIPs     map[string]struct{}
	mispIPs    map[string]struct{}
	csvRows    map[string]map[string]string
	mispRows   map[string]map[string]string
	tierCounts map[string]int
}

// Validate validates publication files from fsys without writing to it.
func Validate(fsys fs.FS) Result {
	return validate(fsys, validationOptions{displayRoot: "."})
}

// ValidateDir validates publication files rooted at dir without writing them.
func ValidateDir(dir string) Result {
	return validate(os.DirFS(dir), validationOptions{displayRoot: dir})
}

func validate(fsys fs.FS, options validationOptions) Result {
	state := validationState{
		fsys:     fsys,
		options:  options,
		jsonIPs:  make(map[string]struct{}),
		csvIPs:   make(map[string]struct{}),
		txtIPs:   make(map[string]struct{}),
		mispIPs:  make(map[string]struct{}),
		csvRows:  make(map[string]map[string]string),
		mispRows: make(map[string]map[string]string),
	}

	for _, name := range []string{"blocklist.json", "blocklist.txt", "blocklist.csv"} {
		if _, err := fs.Stat(fsys, name); err != nil {
			if errorsIsNotExist(err) {
				state.err(fmt.Sprintf("missing required file: %s", displayPath(options.displayRoot, name)))
			} else {
				state.err(fmt.Sprintf("cannot access required file %s: %v", displayPath(options.displayRoot, name), err))
			}
		}
	}
	if len(state.result.Errors) != 0 {
		return state.result
	}

	root, ok := state.readJSON()
	if !ok {
		return state.result
	}
	meta, ok := root["meta"].(map[string]any)
	if !ok {
		state.err("blocklist.json meta must be an object")
		return state.result
	}
	rawEntries, ok := root["ips"].([]any)
	if !ok {
		state.err("blocklist.json ips must be an array")
		return state.result
	}

	state.checkMeta(meta)
	if len(rawEntries) == 0 {
		state.err("blocklist.json contains no entries")
		return state.result
	}
	state.checkEntries(meta, rawEntries)
	state.checkMetaCounts(meta, len(rawEntries))
	state.checkTXT()
	state.checkCSV()
	state.checkMISP()
	state.compareMembership()
	state.compareValues()
	state.checkREADME(len(rawEntries))

	return state.result
}

func (s *validationState) readJSON() (map[string]any, bool) {
	raw, err := fs.ReadFile(s.fsys, "blocklist.json")
	if err != nil {
		s.err(fmt.Sprintf("cannot read blocklist.json: %v", err))
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		s.err(fmt.Sprintf("blocklist.json is not valid JSON: %v", err))
		return nil, false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			s.err("blocklist.json contains more than one JSON value")
		} else {
			s.err(fmt.Sprintf("blocklist.json has trailing invalid data: %v", err))
		}
		return nil, false
	}
	root, ok := decoded.(map[string]any)
	if !ok {
		s.err("blocklist.json must be an object with 'meta' and 'ips'")
		return nil, false
	}
	if _, metaOK := root["meta"]; !metaOK {
		s.err("blocklist.json must be an object with 'meta' and 'ips'")
		return nil, false
	}
	if _, entriesOK := root["ips"]; !entriesOK {
		s.err("blocklist.json must be an object with 'meta' and 'ips'")
		return nil, false
	}
	return root, true
}

func (s *validationState) checkMeta(meta map[string]any) {
	schemaValue, exists := meta["schema_version"]
	if !exists || schemaValue == nil {
		s.warn("meta.schema_version is absent; consumers cannot detect a contract change. Generator should emit '1.0'.")
	} else if schema, ok := schemaValue.(string); !ok || !semverPattern.MatchString(schema) {
		s.err(fmt.Sprintf("meta.schema_version=%s is not MAJOR.MINOR", pythonRepr(schemaValue)))
	} else {
		knownMajor := strings.SplitN(schemaVersion, ".", 2)[0]
		actualMajor := strings.SplitN(schema, ".", 2)[0]
		switch {
		case actualMajor != knownMajor:
			s.err(fmt.Sprintf(
				"meta.schema_version=%s has a different MAJOR than the %s this validator knows. A MAJOR bump means columns were renamed, removed or reordered -- update CSV_COLUMNS and SCHEMA_VERSION together, deliberately.",
				pythonRepr(schema), pythonRepr(schemaVersion),
			))
		case schema != schemaVersion:
			s.warn(fmt.Sprintf(
				"meta.schema_version=%s, validator knows %s (MINOR drift: a column was appended). Confirm CSV_COLUMNS matches what the generator now writes.",
				pythonRepr(schema), pythonRepr(schemaVersion),
			))
		}
	}

	if missing := missingKeys(meta, requiredMeta); len(missing) != 0 {
		s.err(fmt.Sprintf("meta is missing keys: %s", pythonStringList(missing)))
	}
}

func (s *validationState) checkEntries(meta map[string]any, rawEntries []any) {
	recidivists := make([]string, 0)
	byTier := make(map[string]int)
	for index, rawEntry := range rawEntries {
		where := fmt.Sprintf("blocklist.json[%d]", index)
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			s.err(fmt.Sprintf("%s: entry must be an object", where))
			continue
		}
		if missing := missingKeys(entry, requiredEntry); len(missing) != 0 {
			s.err(fmt.Sprintf("%s: missing fields %s", where, pythonStringList(missing)))
			continue
		}
		s.entries = append(s.entries, entry)

		ip, ok := s.checkIP(entry["ip"], where)
		if !ok {
			continue
		}
		if _, duplicate := s.jsonIPs[ip]; duplicate {
			s.err(fmt.Sprintf("%s: duplicate entry for %s", where, ip))
		}
		s.jsonIPs[ip] = struct{}{}

		tier, tierIsString := entry["tier"].(string)
		if _, valid := validTiers[tier]; !tierIsString || !valid {
			s.err(fmt.Sprintf("%s: unknown tier %s", where, pythonRepr(entry["tier"])))
		} else {
			byTier[tier]++
		}

		asn, asnIsString := entry["asn"].(string)
		if !asnIsString || !asnPattern.MatchString(asn) {
			s.err(fmt.Sprintf("%s: asn must match AS<number>, got %s", where, pythonRepr(entry["asn"])))
		}

		bans, bansOK := strictNonNegativeInt(entry["bans"])
		if !bansOK {
			s.err(fmt.Sprintf("%s: bans must be a non-negative int, got %s", where, pythonRepr(entry["bans"])))
		}
		attempts, attemptsOK := strictNonNegativeInt(entry["attempts"])
		if !attemptsOK {
			s.err(fmt.Sprintf("%s: attempts must be a non-negative int, got %s", where, pythonRepr(entry["attempts"])))
		}
		if tier == "scanner" && bansOK && bans != 0 {
			s.err(fmt.Sprintf("%s: scanner-tier entry has bans=%d, expected 0", where, bans))
		}
		floor, hasFloor := tierMinimumAttempts[tier]
		if tier == "scanner" {
			if declared, ok := strictPositiveInt(meta["scanner_min_events"]); ok {
				floor = declared
				hasFloor = true
			}
		}
		if hasFloor && attemptsOK && attempts < floor {
			s.err(fmt.Sprintf(
				"%s: %s-tier entry has attempts=%d, below the documented inclusion threshold of %d. meta.inclusion_criteria promises this floor to every consumer -- publishing under it lists an address the stated criteria do not justify.",
				where, tier, attempts, floor,
			))
		}

		firstSeen, firstSeenOK := s.checkRequiredTimestamp(entry["first_seen"], where, "first_seen")
		lastSeen, lastSeenOK := s.checkRequiredTimestamp(entry["last_seen"], where, "last_seen")
		if firstSeenOK && lastSeenOK && firstSeen > lastSeen {
			s.err(fmt.Sprintf("%s: first_seen %s is after last_seen %s", where, firstSeen, lastSeen))
		}

		firstBanned, hasFirstBanned := optionalString(entry["first_banned"])
		if entry["first_banned"] != nil && !hasFirstBanned {
			s.err(fmt.Sprintf("%s: first_banned must be a string or null, got %s", where, pythonRepr(entry["first_banned"])))
		}
		if bansOK && bans == 0 && hasFirstBanned && firstBanned != "" {
			s.err(fmt.Sprintf("%s: bans=0 but first_banned=%s", where, pythonRepr(firstBanned)))
		}
		if bansOK && bans > 0 && (!hasFirstBanned || firstBanned == "") {
			s.err(fmt.Sprintf("%s: bans=%d but first_banned is empty", where, bans))
		}
		if hasFirstBanned && firstBanned != "" {
			if reason := badTimestamp(firstBanned); reason != "" {
				s.err(fmt.Sprintf("%s: first_banned=%s %s", where, pythonRepr(firstBanned), reason))
			}
			if firstSeenOK && firstBanned < firstSeen {
				recidivists = append(recidivists, ip)
			}
		}
	}

	if len(recidivists) != 0 {
		sample := recidivists
		if len(sample) > 3 {
			sample = sample[:3]
		}
		s.warn(fmt.Sprintf(
			"%d of %d entries have first_banned before first_seen (expected: see the column contract in README.md). Sample: %s",
			len(recidivists), len(rawEntries), pythonStringList(sample),
		))
	}
	s.tierCounts = byTier
}

func (s *validationState) checkRequiredTimestamp(value any, where, field string) (string, bool) {
	text, ok := value.(string)
	if !ok {
		s.err(fmt.Sprintf("%s: %s must be a string, got %s", where, field, pythonRepr(value)))
		return "", false
	}
	if text == "" {
		s.err(fmt.Sprintf("%s: %s is empty", where, field))
		return "", false
	}
	if reason := badTimestamp(text); reason != "" {
		s.err(fmt.Sprintf("%s: %s=%s %s", where, field, pythonRepr(text), reason))
		return text, false
	}
	return text, true
}

func (s *validationState) checkMetaCounts(meta map[string]any, entryCount int) {
	count, ok := strictNonNegativeInt(meta["count"])
	if !ok || count != int64(entryCount) {
		s.err(fmt.Sprintf("meta.count=%s but %d entries present", pythonRepr(meta["count"]), entryCount))
	}
	actual := s.tierCounts
	declared, ok := stringIntMap(meta["count_by_tier"])
	if !ok || !equalStringIntMaps(declared, actual) {
		s.err(fmt.Sprintf("meta.count_by_tier=%s but actual is %s", pythonRepr(meta["count_by_tier"]), pythonIntMap(actual)))
	}
}

func (s *validationState) err(message string) {
	s.result.Errors = append(s.result.Errors, message)
}

func (s *validationState) warn(message string) {
	s.result.Warnings = append(s.result.Warnings, message)
}

func missingKeys(object map[string]any, required []string) []string {
	missing := make([]string, 0)
	for _, key := range required {
		if _, exists := object[key]; !exists {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	return missing
}

func strictNonNegativeInt(value any) (int64, bool) {
	integer, ok := strictInt(value)
	return integer, ok && integer >= 0
}

func strictPositiveInt(value any) (int64, bool) {
	integer, ok := strictInt(value)
	return integer, ok && integer > 0
}

func strictInt(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	integer, err := strconv.ParseInt(string(number), 10, 64)
	return integer, err == nil
}

func optionalString(value any) (string, bool) {
	if value == nil {
		return "", true
	}
	text, ok := value.(string)
	return text, ok
}

func stringIntMap(value any) (map[string]int, bool) {
	raw, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	converted := make(map[string]int, len(raw))
	for key, item := range raw {
		integer, ok := strictNonNegativeInt(item)
		if !ok {
			return nil, false
		}
		converted[key] = int(integer)
	}
	return converted, true
}

func equalStringIntMaps(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func pythonIntMap(values map[string]int) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s: %d", pythonRepr(key), values[key]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func pythonStringList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, pythonRepr(value))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func pythonRepr(value any) string {
	switch typed := value.(type) {
	case nil:
		return "None"
	case string:
		escaped := strings.NewReplacer(
			`\`, `\\`,
			`'`, `\'`,
			"\t", `\t`,
			"\r", `\r`,
			"\n", `\n`,
		).Replace(typed)
		return "'" + escaped + "'"
	case bool:
		if typed {
			return "True"
		}
		return "False"
	case json.Number:
		return string(typed)
	default:
		encoded, err := json.Marshal(typed)
		if err == nil {
			return string(encoded)
		}
		return fmt.Sprintf("%v", typed)
	}
}

func displayPath(root, name string) string {
	if root == "" || root == "." {
		return "./" + name
	}
	return filepath.Join(root, name)
}

func errorsIsNotExist(err error) bool {
	return os.IsNotExist(err)
}
