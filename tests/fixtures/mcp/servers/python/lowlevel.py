"""The same tools on the low-level server class, aliased on import."""

import anyio
from mcp.server.lowlevel import Server as LowLevelServer
from mcp.server.stdio import stdio_server

server = LowLevelServer("arithmetic-lowlevel")


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
