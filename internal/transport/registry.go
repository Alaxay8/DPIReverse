package transport

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type Runner interface {
	Run(context.Context, model.TestCase) (map[string]string, error)
}

type Registry struct {
	runners map[model.Protocol]Runner
}

func NewRegistry(logger *slog.Logger, proxyURL string) *Registry {
	return &Registry{
		runners: map[model.Protocol]Runner{
			model.ProtocolTCP:       &TCPRunner{proxyURL: proxyURL},
			model.ProtocolUDP:       &UDPRunner{proxyURL: proxyURL},
			model.ProtocolTLS:       &TLSRunner{logger: logger, proxyURL: proxyURL},
			model.ProtocolWebSocket: &WebSocketRunner{proxyURL: proxyURL},
			model.ProtocolHTTP:      &HTTPRunner{logger: logger, proxyURL: proxyURL},
			model.ProtocolHTTP2:     &HTTP2Runner{logger: logger, proxyURL: proxyURL},
			model.ProtocolHTTP3:     &HTTP3Runner{logger: logger, proxyURL: proxyURL},
		},
	}
}

func (r *Registry) RunnerFor(protocol model.Protocol) (Runner, error) {
	runner, ok := r.runners[protocol]
	if !ok {
		return nil, fmt.Errorf("no runner registered for protocol %q", protocol)
	}

	return runner, nil
}
