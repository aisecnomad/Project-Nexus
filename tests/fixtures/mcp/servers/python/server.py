"""A FastMCP server with two arithmetic tools, served over stdio."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("arithmetic")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


@mcp.tool(description="Multiply two integers")
def multiply(a: int, b: int) -> int:
    return a * b


if __name__ == "__main__":
    mcp.run(transport="stdio")
