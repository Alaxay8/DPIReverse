package model

import (
	"fmt"
	"math"
	"net"
	"slices"
	"time"
)

type Protocol string

const (
	ProtocolTCP       Protocol = "tcp"
	ProtocolUDP       Protocol = "udp"
	ProtocolTLS       Protocol = "tls"
	ProtocolWebSocket Protocol = "websocket"
	ProtocolHTTP      Protocol = "http"
	ProtocolHTTP2     Protocol = "http2"
	ProtocolHTTP3     Protocol = "http3"
)

type Profile string

const (
	ProfileQuick Profile = "quick"
	ProfileFull  Profile = "full"
)

type OutputFormat string

const (
	OutputJSON OutputFormat = "json"
	OutputText OutputFormat = "text"
)

type ErrorType string

const (
	ErrorTypeNone     ErrorType = "none"
	ErrorTypeTimeout  ErrorType = "timeout"
	ErrorTypeRST      ErrorType = "rst"
	ErrorTypeFIN      ErrorType = "fin"
	ErrorTypeRefused  ErrorType = "refused"
	ErrorTypeTLS      ErrorType = "tls"
	ErrorTypeProtocol ErrorType = "protocol"
	ErrorTypeUnknown  ErrorType = "unknown"
)

type ScanRequest struct {
	Target       Target
	Profile      Profile
	OutputFormat OutputFormat
	Repeats      int
	Timeout      time.Duration
	Concurrency  int
	ProxyURL     string
}

type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (t Target) Address() string {
	port := t.Port
	if port == 0 {
		port = 443
	}

	return net.JoinHostPort(t.Host, fmt.Sprintf("%d", port))
}

type TestCase struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Group     string            `json:"group"`
	Protocol  Protocol          `json:"protocol"`
	Target    Target            `json:"target"`
	Repeats   int               `json:"repeats"`
	Timeout   time.Duration     `json:"timeout"`
	Tags      map[string]string `json:"tags,omitempty"`
	TLS       *TLSOptions       `json:"tls,omitempty"`
	TCP       *TCPOptions       `json:"tcp,omitempty"`
	UDP       *UDPOptions       `json:"udp,omitempty"`
	WebSocket *WebSocketOptions `json:"websocket,omitempty"`
	HTTP      *HTTPOptions      `json:"http,omitempty"`
	HTTP3     *HTTP3Options     `json:"http3,omitempty"`
}

type TLSOptions struct {
	ServerName         string                `json:"server_name"`
	ClientHelloProfile string                `json:"client_hello_profile"`
	MinVersion         uint16                `json:"min_version"`
	MaxVersion         uint16                `json:"max_version"`
	Fragmentation      *FragmentationOptions `json:"fragmentation,omitempty"`
}

type FragmentationOptions struct {
	ChunkSize int           `json:"chunk_size"`
	Delay     time.Duration `json:"delay"`
}

type TCPOptions struct {
	Payload []byte `json:"payload,omitempty"`
}

type UDPOptions struct {
	Payload []byte `json:"payload,omitempty"`
}

type WebSocketOptions struct {
	Path    string            `json:"path,omitempty"`
	Secure  bool              `json:"secure"`
	Headers map[string]string `json:"headers,omitempty"`
}

type HTTPOptions struct {
	Version          string            `json:"version,omitempty"`
	Method           string            `json:"method,omitempty"`
	Path             string            `json:"path,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	RandomizeHeaders bool              `json:"randomize_headers,omitempty"`
	UserAgent        string            `json:"user_agent,omitempty"`
}

type HTTP3Options struct {
	Method string            `json:"method,omitempty"`
	Path   string            `json:"path,omitempty"`
}

type Measurement struct {
	TestID       string            `json:"test_id"`
	Attempt      int               `json:"attempt"`
	Protocol     Protocol          `json:"protocol"`
	Success      bool              `json:"success"`
	LatencyMS    int64             `json:"latency_ms"`
	ErrorType    ErrorType         `json:"error_type"`
	ErrorMessage string            `json:"error_message,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type TestResult struct {
	TestID         string            `json:"test_id"`
	Name           string            `json:"name"`
	Group          string            `json:"group"`
	Protocol       Protocol          `json:"protocol"`
	Tags           map[string]string `json:"tags,omitempty"`
	Attempts       int               `json:"attempts"`
	SuccessRate    float64           `json:"success_rate"`
	MeanLatencyMS  float64           `json:"mean_latency_ms"`
	ErrorBreakdown map[ErrorType]int `json:"error_breakdown"`
	Measurements   []Measurement     `json:"measurements"`
}

type DPIProfile struct {
	SNIFiltering        bool `json:"sni_filtering"`
	JA3Blocking         bool `json:"ja3_blocking"`
	FragmentationBypass bool `json:"fragmentation_bypass"`
}

type AnalysisFinding struct {
	Key        string   `json:"key"`
	Detected   bool     `json:"detected"`
	Confidence float64  `json:"confidence"`
	Summary    string   `json:"summary"`
	Evidence   []string `json:"evidence,omitempty"`
}

type AnalysisResult struct {
	DPIProfile DPIProfile        `json:"dpi_profile"`
	Confidence float64           `json:"confidence"`
	Findings   []AnalysisFinding `json:"findings"`
}

type ScanReport struct {
	Target       string         `json:"target"`
	Profile      Profile        `json:"profile"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  time.Time      `json:"completed_at"`
	Results      []TestResult   `json:"results"`
	Measurements []Measurement  `json:"measurements"`
	Analysis     AnalysisResult `json:"analysis"`
}

func NormalizeConfidence(value float64) float64 {
	clamped := min(max(value, 0), 1)
	return math.Round(clamped*100) / 100
}

func OrderedErrorKeys(counts map[ErrorType]int) []ErrorType {
	keys := make([]ErrorType, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
