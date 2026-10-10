package sdk

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func Run(ctx context.Context) error {
	srv := mcp.NewServer(&mcp.Implementation{Name: "arithmetic", Version: "1.0.0"}, nil)
	return srv.Run(ctx, &mcp.StdioTransport{})
}
