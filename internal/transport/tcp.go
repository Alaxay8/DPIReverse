package transport

import (
	"context"
	"fmt"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type TCPRunner struct {
	proxyURL string
}

func (r *TCPRunner) Run(ctx context.Context, test model.TestCase) (map[string]string, error) {
	conn, err := ProxyDialer(ctx, "tcp", test.Target.Address(), r.proxyURL)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if test.TCP != nil && len(test.TCP.Payload) > 0 {
		if _, err := conn.Write(test.TCP.Payload); err != nil {
			return nil, fmt.Errorf("write tcp payload: %w", err)
		}
	}

	return map[string]string{"address": test.Target.Address()}, nil
}
