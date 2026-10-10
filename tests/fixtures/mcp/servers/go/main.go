package main

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("arithmetic", "1.0.0")
	s.AddTool(mcp.NewTool("add", mcp.WithDescription("Add two integers")), nil)
	_ = server.ServeStdio(s)
}
