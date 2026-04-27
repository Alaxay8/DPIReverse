package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type UDPRunner struct {
	proxyURL string
}

func (r *UDPRunner) Run(ctx context.Context, test model.TestCase) (map[string]string, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", test.Target.Address())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if test.UDP != nil && len(test.UDP.Payload) > 0 {
		if _, err := conn.Write(test.UDP.Payload); err != nil {
			return nil, fmt.Errorf("write udp payload: %w", err)
		}
	}

	return map[string]string{"address": test.Target.Address()}, nil
}
