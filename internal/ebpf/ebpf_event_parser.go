package ebpf

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EventScanner parses bpftrace output and converts it to TraceEvent structs
type EventScanner struct {
	scanner   *bufio.Scanner
	lastEvent *TraceEvent
	lineRegex *regexp.Regexp
}

// NewEventScanner creates a new event scanner for parsing bpftrace output
func NewEventScanner(reader io.Reader) *EventScanner {
	// Regex pattern to match our trace output format:
	// TRACE|timestamp|pid|tid|comm|function|message
	pattern := `^TRACE\|(\d+)\|(\d+)\|(\d+)\|([^|]+)\|([^|]+)\|(.*)$`
	regex, _ := regexp.Compile(pattern)

	return &EventScanner{
		scanner:   bufio.NewScanner(reader),
		lineRegex: regex,
	}
}

// Scan advances the scanner to the next event
func (es *EventScanner) Scan() bool {
	for es.scanner.Scan() {
		line := strings.TrimSpace(es.scanner.Text())

		// Skip empty lines and non-trace lines
		if line == "" || !strings.HasPrefix(line, "TRACE|") {
			continue
		}

		// Parse the trace line
		if event := es.parseLine(line); event != nil {
			es.lastEvent = event
			return true
		}
	}

	return false
}

// Event returns the most recently parsed event
func (es *EventScanner) Event() *TraceEvent {
	return es.lastEvent
}

// Error returns any scanning error
func (es *EventScanner) Error() error {
	return es.scanner.Err()
}

// parseLine parses a single trace line into a TraceEvent
func (es *EventScanner) parseLine(line string) *TraceEvent {
	matches := es.lineRegex.FindStringSubmatch(line)
	if len(matches) != 7 {
		return nil
	}

	// Parse timestamp (nanoseconds)
	timestamp, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return nil
	}

	// Parse PID
	pid, err := strconv.Atoi(matches[2])
	if err != nil {
		return nil
	}

	// Parse TID
	tid, err := strconv.Atoi(matches[3])
	if err != nil {
		return nil
	}

	// Extract process name, function, and message
	processName := strings.TrimSpace(matches[4])
	function := strings.TrimSpace(matches[5])
	message := strings.TrimSpace(matches[6])

	event := &TraceEvent{
		Timestamp:   timestamp,
		PID:         pid,
		TID:         tid,
		ProcessName: processName,
		Function:    function,
		Message:     message,
		RawArgs:     make(map[string]string),
	}

	// Try to extract additional information from the message
	es.enrichEvent(event, message)

	return event
}

// enrichEvent extracts additional information from the message
func (es *EventScanner) enrichEvent(event *TraceEvent, message string) {
	// Parse common patterns in messages to extract arguments
	// This is a simplified version - in a real implementation you'd want more sophisticated parsing

	// Look for patterns like "arg1=value, arg2=value"
	argPattern := regexp.MustCompile(`(\w+)=([^,\s]+)`)
	matches := argPattern.FindAllStringSubmatch(message, -1)

	for _, match := range matches {
		if len(match) == 3 {
			event.RawArgs[match[1]] = match[2]
		}
	}

	// Look for numeric patterns that might be syscall arguments
	numberPattern := regexp.MustCompile(`\b(\d+)\b`)
	numbers := numberPattern.FindAllString(message, -1)

	for i, num := range numbers {
		argName := "arg" + strconv.Itoa(i+1)
		event.RawArgs[argName] = num
	}
}

// TraceEventFilter provides filtering capabilities for trace events
type TraceEventFilter struct {
	MinTimestamp  int64
	MaxTimestamp  int64
	ProcessNames  []string
	PIDs          []int
	UIDs          []int
	Functions     []string
	MessageFilter string
}

// ApplyFilter applies filters to a slice of events
func (filter *TraceEventFilter) ApplyFilter(events []TraceEvent) []TraceEvent {
	if filter == nil {
		return events
	}

	var filtered []TraceEvent

	for _, event := range events {
		if filter.matchesEvent(&event) {
			filtered = append(filtered, event)
		}
	}

	return filtered
}

// matchesEvent checks if an event matches the filter criteria
func (filter *TraceEventFilter) matchesEvent(event *TraceEvent) bool {
	// Check timestamp range
	if filter.MinTimestamp > 0 && event.Timestamp < filter.MinTimestamp {
		return false
	}
	if filter.MaxTimestamp > 0 && event.Timestamp > filter.MaxTimestamp {
		return false
	}

	// Check process names
	if len(filter.ProcessNames) > 0 {
		found := false
		for _, name := range filter.ProcessNames {
			if strings.Contains(event.ProcessName, name) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check PIDs
	if len(filter.PIDs) > 0 {
		found := false
		for _, pid := range filter.PIDs {
			if event.PID == pid {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check UIDs
	if len(filter.UIDs) > 0 {
		found := false
		for _, uid := range filter.UIDs {
			if event.UID == uid {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check functions
	if len(filter.Functions) > 0 {
		found := false
		for _, function := range filter.Functions {
			if strings.Contains(event.Function, function) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check message filter
	if filter.MessageFilter != "" {
		if !strings.Contains(event.Message, filter.MessageFilter) {
			return false
		}
	}

	return true
}

// TraceEventAggregator provides aggregation capabilities for trace events
type TraceEventAggregator struct {
	events []TraceEvent
}

// NewTraceEventAggregator creates a new event aggregator
func NewTraceEventAggregator(events []TraceEvent) *TraceEventAggregator {
	return &TraceEventAggregator{
		events: events,
	}
}

// CountByProcess returns event counts grouped by process
func (agg *TraceEventAggregator) CountByProcess() map[string]int {
	counts := make(map[string]int)
	for _, event := range agg.events {
		counts[event.ProcessName]++
	}
	return counts
}

// CountByFunction returns event counts grouped by function
func (agg *TraceEventAggregator) CountByFunction() map[string]int {
	counts := make(map[string]int)
	for _, event := range agg.events {
		counts[event.Function]++
	}
	return counts
}

// CountByPID returns event counts grouped by PID
func (agg *TraceEventAggregator) CountByPID() map[int]int {
	counts := make(map[int]int)
	for _, event := range agg.events {
		counts[event.PID]++
	}
	return counts
}

// GetTimeRange returns the time range of events
func (agg *TraceEventAggregator) GetTimeRange() (int64, int64) {
	if len(agg.events) == 0 {
		return 0, 0
	}

	minTime := agg.events[0].Timestamp
	maxTime := agg.events[0].Timestamp

	for _, event := range agg.events {
		if event.Timestamp < minTime {
			minTime = event.Timestamp
		}
		if event.Timestamp > maxTime {
			maxTime = event.Timestamp
		}
	}

	return minTime, maxTime
}

// GetEventRate calculates events per second
func (agg *TraceEventAggregator) GetEventRate() float64 {
	if len(agg.events) < 2 {
		return 0
	}

	minTime, maxTime := agg.GetTimeRange()
	durationNs := maxTime - minTime
	durationSeconds := float64(durationNs) / float64(time.Second)

	if durationSeconds == 0 {
		return 0
	}

	return float64(len(agg.events)) / durationSeconds
}

// GetTopProcesses returns the most active processes
func (agg *TraceEventAggregator) GetTopProcesses(limit int) []ProcessStat {
	counts := agg.CountByProcess()
	total := len(agg.events)

	var stats []ProcessStat
	for processName, count := range counts {
		percentage := float64(count) / float64(total) * 100
		stats = append(stats, ProcessStat{
			ProcessName: processName,
			EventCount:  count,
			Percentage:  percentage,
		})
	}

	// Simple sorting by event count (bubble sort for simplicity)
	for i := 0; i < len(stats); i++ {
		for j := i + 1; j < len(stats); j++ {
			if stats[j].EventCount > stats[i].EventCount {
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}

	if limit > 0 && limit < len(stats) {
		stats = stats[:limit]
	}

	return stats
}
