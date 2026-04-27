package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type HTTPRunner struct {
	logger   *slog.Logger
	proxyURL string
}

func (r *HTTPRunner) Run(ctx context.Context, test model.TestCase) (map[string]string, error) {
	if test.HTTP == nil {
		test.HTTP = &model.HTTPOptions{
			Method: "GET",
			Path:   "/",
		}
	}

	method := test.HTTP.Method
	if method == "" {
		method = "GET"
	}
	path := test.HTTP.Path
	if path == "" {
		path = "/"
	}

	url := fmt.Sprintf("http://%s%s", test.Target.Host, path)
	if test.TLS != nil || test.Protocol == model.ProtocolTLS {
		url = fmt.Sprintf("https://%s%s", test.Target.Host, path)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range test.HTTP.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	metadata := map[string]string{
		"proto":  resp.Proto,
		"status": resp.Status,
	}

	return metadata, nil
}
