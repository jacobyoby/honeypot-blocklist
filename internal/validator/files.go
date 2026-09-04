package validator

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"io/fs"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *validationState) checkTXT() {
	file, err := s.fsys.Open("blocklist.txt")
	if err != nil {
		s.err(fmt.Sprintf("cannot read blocklist.txt: %v", err))
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ip, ok := s.checkIP(line, fmt.Sprintf("blocklist.txt:%d", lineNumber)); ok {
			if _, duplicate := s.txtIPs[ip]; duplicate {
				s.err(fmt.Sprintf("blocklist.txt:%d: duplicate %s", lineNumber, ip))
			}
			s.txtIPs[ip] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		s.err(fmt.Sprintf("cannot parse blocklist.txt: %v", err))
	}
}

func (s *validationState) checkCSV() {
	records, ok := s.readCSV("blocklist.csv")
	if !ok {
		return
	}
	for index, record := range records {
		lineNumber := index + 1
		if len(record) == 0 {
			continue
		}
		if len(record) != len(csvColumns) {
			s.err(fmt.Sprintf(
				"blocklist.csv:%d: %d columns, expected %d (%s). DictReader would have accepted this silently.",
				lineNumber, len(record), len(csvColumns), strings.Join(csvColumns, ","),
			))
		}
		if lineNumber > 1 {
			for columnIndex, cell := range record {
				if columnIndex >= len(csvColumns) {
					break
				}
				s.checkCell(cell, fmt.Sprintf("blocklist.csv:%d.%s", lineNumber, csvColumns[columnIndex]))
			}
		}
	}

	if len(records) == 0 || !equalStrings(records[0], csvColumns) {
		var header []string
		if len(records) != 0 {
			header = records[0]
		}
		s.err(fmt.Sprintf(
			"blocklist.csv header %s does not match the published column contract %s. Column order is load-bearing for MISP/OpenCTI; append only, never reorder.",
			pythonStringList(header), pythonStringList(csvColumns),
		))
		return
	}

	for index, record := range records[1:] {
		lineNumber := index + 2
		if len(record) != len(csvColumns) {
			continue
		}
		row := make(map[string]string, len(csvColumns))
		for columnIndex, column := range csvColumns {
			row[column] = record[columnIndex]
		}
		ip, ipOK := s.checkIP(row["ip"], fmt.Sprintf("blocklist.csv:%d", lineNumber))
		if ipOK {
			if _, duplicate := s.csvIPs[ip]; duplicate {
				s.err(fmt.Sprintf("blocklist.csv:%d: duplicate %s", lineNumber, ip))
			}
			s.csvIPs[ip] = struct{}{}
		}
		if _, valid := validTiers[row["tier"]]; !valid {
			s.err(fmt.Sprintf("blocklist.csv:%d: unknown tier %s", lineNumber, pythonRepr(row["tier"])))
		}
		if !asnPattern.MatchString(row["asn"]) {
			s.err(fmt.Sprintf("blocklist.csv:%d: asn must match AS<number>, got %s", lineNumber, pythonRepr(row["asn"])))
		}
		where := fmt.Sprintf("blocklist.csv:%d", lineNumber)
		for _, field := range []string{"first_seen", "last_seen"} {
			if row[field] == "" {
				s.err(fmt.Sprintf("%s: %s is empty", where, field))
				continue
			}
			if reason := badTimestamp(row[field]); reason != "" {
				s.err(fmt.Sprintf("%s: %s=%s %s", where, field, pythonRepr(row[field]), reason))
			}
		}
		if row["first_banned"] != "" {
			if reason := badTimestamp(row["first_banned"]); reason != "" {
				s.err(fmt.Sprintf("%s: first_banned=%s %s", where, pythonRepr(row["first_banned"]), reason))
			}
		}
		if _, duplicate := s.csvRows[row["ip"]]; duplicate {
			s.err(fmt.Sprintf("blocklist.csv:%d: duplicate row for %s", lineNumber, row["ip"]))
		}
		s.csvRows[row["ip"]] = row
	}
}

func (s *validationState) checkMISP() {
	if _, err := fs.Stat(s.fsys, "blocklist.misp.csv"); err != nil {
		if errorsIsNotExist(err) {
			s.err("blocklist.misp.csv is missing. It is the documented MISP/OpenCTI feed (README.md and meta.formats.csv_headerless both point at it); publishing without it silently breaks those consumers.")
		} else {
			s.err(fmt.Sprintf("cannot access blocklist.misp.csv: %v", err))
		}
		return
	}
	records, ok := s.readCSV("blocklist.misp.csv")
	if !ok {
		return
	}
	if len(records) != 0 && len(records[0]) != 0 && strings.EqualFold(strings.TrimSpace(records[0][0]), "ip") {
		s.err("blocklist.misp.csv starts with a header row; MISP would ingest it as data. It must be header-less.")
	}
	for index, record := range records {
		lineNumber := index + 1
		if len(record) == 0 {
			continue
		}
		if len(record) != len(csvColumns) {
			s.err(fmt.Sprintf(
				"blocklist.misp.csv:%d: %d columns, expected %d (%s)",
				lineNumber, len(record), len(csvColumns), strings.Join(csvColumns, ","),
			))
			continue
		}
		for columnIndex, cell := range record {
			s.checkCell(cell, fmt.Sprintf("blocklist.misp.csv:%d.%s", lineNumber, csvColumns[columnIndex]))
		}
		ip, ipOK := s.checkIP(record[0], fmt.Sprintf("blocklist.misp.csv:%d", lineNumber))
		if ipOK {
			if _, duplicate := s.mispIPs[ip]; duplicate {
				s.err(fmt.Sprintf("blocklist.misp.csv:%d: duplicate %s", lineNumber, ip))
			}
			s.mispIPs[ip] = struct{}{}
			row := make(map[string]string, len(csvColumns))
			for columnIndex, column := range csvColumns {
				row[column] = record[columnIndex]
			}
			s.mispRows[ip] = row
		}
		if _, valid := validTiers[record[1]]; !valid {
			s.err(fmt.Sprintf("blocklist.misp.csv:%d: unknown tier %s", lineNumber, pythonRepr(record[1])))
		}
		if !asnPattern.MatchString(record[7]) {
			s.err(fmt.Sprintf("blocklist.misp.csv:%d: asn must match AS<number>, got %s", lineNumber, pythonRepr(record[7])))
		}
	}
	if !equalSets(s.mispIPs, s.jsonIPs) {
		s.err(fmt.Sprintf(
			"blocklist.misp.csv names a different set than blocklist.json (%d vs %d)",
			len(s.mispIPs), len(s.jsonIPs),
		))
	}
}

func (s *validationState) compareMembership() {
	if !equalSets(s.jsonIPs, s.txtIPs) {
		onlyJSON, onlyTXT := setDifference(s.jsonIPs, s.txtIPs), setDifference(s.txtIPs, s.jsonIPs)
		s.err(fmt.Sprintf(
			"json/txt disagree: %d only in json %s, %d only in txt %s",
			len(onlyJSON), pythonStringList(firstThree(onlyJSON)),
			len(onlyTXT), pythonStringList(firstThree(onlyTXT)),
		))
	}
	if !equalSets(s.jsonIPs, s.csvIPs) {
		onlyJSON, onlyCSV := setDifference(s.jsonIPs, s.csvIPs), setDifference(s.csvIPs, s.jsonIPs)
		s.err(fmt.Sprintf(
			"json/csv disagree: %d only in json %s, %d only in csv %s",
			len(onlyJSON), pythonStringList(firstThree(onlyJSON)),
			len(onlyCSV), pythonStringList(firstThree(onlyCSV)),
		))
	}
}

func (s *validationState) compareValues() {
	shared := []string{"tier", "bans", "attempts", "first_seen", "last_seen", "first_banned", "asn"}
	mismatches := make([]string, 0)
	for _, entry := range s.entries {
		ip, ok := entry["ip"].(string)
		if !ok {
			continue
		}
		row, exists := s.csvRows[ip]
		if !exists {
			continue
		}
		for _, field := range shared {
			jsonValue := valueAsPublishedString(entry[field])
			csvValue := row[field]
			if jsonValue != csvValue {
				mismatches = append(mismatches, fmt.Sprintf(
					"%s.%s: json=%s csv=%s",
					ip, field, pythonRepr(jsonValue), pythonRepr(csvValue),
				))
			}
		}
	}
	if len(mismatches) != 0 {
		sample := mismatches
		if len(sample) > 3 {
			sample = sample[:3]
		}
		s.err(fmt.Sprintf(
			"json and csv disagree on %d field value(s): %s",
			len(mismatches), pythonStringList(sample),
		))
	}

	mispMismatches := make([]string, 0)
	for ip, csvRow := range s.csvRows {
		mispRow, exists := s.mispRows[ip]
		if !exists {
			continue
		}
		for _, field := range csvColumns {
			if csvRow[field] != mispRow[field] {
				mispMismatches = append(mispMismatches, fmt.Sprintf(
					"%s.%s: csv=%s misp=%s",
					ip, field, pythonRepr(csvRow[field]), pythonRepr(mispRow[field]),
				))
			}
		}
	}
	if len(mispMismatches) != 0 {
		sort.Strings(mispMismatches)
		sample := mispMismatches
		if len(sample) > 3 {
			sample = sample[:3]
		}
		s.err(fmt.Sprintf(
			"csv and blocklist.misp.csv disagree on %d field value(s): %s",
			len(mispMismatches), pythonStringList(sample),
		))
	}
}

func (s *validationState) checkREADME(entryCount int) {
	if _, err := fs.Stat(s.fsys, "README.md"); err != nil {
		return
	}
	raw, err := fs.ReadFile(s.fsys, "README.md")
	if err != nil {
		s.warn(fmt.Sprintf("README could not be read: %v", err))
		return
	}
	readme := string(raw)
	countToken := fmt.Sprintf("**%d IPs**", entryCount)
	if !strings.Contains(readme, countToken) {
		s.warn(fmt.Sprintf("README does not state the current count (%s) — it drifted out of date once before", countToken))
	}

	match := measuredAtPattern.FindStringSubmatch(readme)
	if match == nil {
		s.warn("README does not record the date and feed size its overlap/novelty claims were measured against, so nothing can tell whether they still describe the published list. Expected a phrase like 'measured 2026-08-24 ... against the live 153-entry feed'.")
		return
	}
	measuredSize, err := strconv.Atoi(strings.ReplaceAll(match[2], ",", ""))
	if err != nil {
		s.warn(fmt.Sprintf("README's measured feed size %s is invalid", pythonRepr(match[2])))
		return
	}
	drift := 1.0
	if measuredSize != 0 {
		drift = math.Abs(float64(entryCount-measuredSize)) / float64(measuredSize)
	}
	if drift > claimDriftTolerance {
		s.warn(fmt.Sprintf(
			"README's overlap/novelty claims were measured %s against %d entries; the feed is now %d (%.0f%% drift, tolerance %.0f%%). Those figures are percentages OF the feed, so they now describe a different list. Re-run scripts/overlap.py and update README.",
			match[1], measuredSize, entryCount, drift*100, claimDriftTolerance*100,
		))
	}
}

func (s *validationState) readCSV(name string) ([][]string, bool) {
	file, err := s.fsys.Open(name)
	if err != nil {
		s.err(fmt.Sprintf("cannot read %s: %v", name, err))
		return nil, false
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	records := make([][]string, 0)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.err(fmt.Sprintf("%s is not valid CSV: %v", name, err))
			return records, false
		}
		records = append(records, record)
	}
	return records, true
}

func (s *validationState) checkCell(value, where string) {
	if value == "" {
		return
	}
	first := value[0]
	if first == '\t' || first == '\r' || first == '\n' {
		s.err(fmt.Sprintf(
			"%s: cell %s begins with a control character; a spreadsheet strips it and then evaluates what follows",
			where, pythonRepr(value),
		))
		return
	}
	if first == '=' || first == '+' || first == '-' || first == '@' {
		s.err(fmt.Sprintf(
			"%s: cell %s begins with a formula character (%s); this feed is opened in spreadsheets and the cell would be executed. Nothing legitimate in this feed starts with one.",
			where, pythonRepr(value), pythonRepr(string(first)),
		))
	}
}

func badTimestamp(value string) string {
	if len(value) != len("2006-01-02T15:04:05Z") || value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' || value[16] != ':' || value[19] != 'Z' {
		return "is not ISO-8601 UTC (expected YYYY-MM-DDTHH:MM:SSZ)"
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", value); err != nil {
		return fmt.Sprintf("is not a real date/time (%v)", err)
	}
	return ""
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalSets(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, exists := right[value]; !exists {
			return false
		}
	}
	return true
}

func setDifference(left, right map[string]struct{}) []string {
	values := make([]string, 0)
	for value := range left {
		if _, exists := right[value]; !exists {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}

func firstThree(values []string) []string {
	if len(values) <= 3 {
		return values
	}
	return values[:3]
}

func valueAsPublishedString(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprintf("%v", typed)
	}
}
