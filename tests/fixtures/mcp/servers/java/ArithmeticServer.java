import io.modelcontextprotocol.server.McpAsyncServer;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;

public final class ArithmeticServer {
    public static McpSyncServer sync(StdioServerTransportProvider transport) {
        return McpServer.sync(transport).serverInfo("arithmetic", "1.0.0").build();
    }

    public static McpAsyncServer async(StdioServerTransportProvider transport) {
        return McpServer.async(transport).serverInfo("arithmetic", "1.0.0").build();
    }
}
