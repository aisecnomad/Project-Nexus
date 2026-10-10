using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Server;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddMcpServer().WithStdioServerTransport().WithToolsFromAssembly();
await builder.Build().RunAsync();

[McpServerToolType]
public static class ArithmeticTools
{
    [McpServerTool, Description("Add two integers")]
    public static int Add(int a, int b) => a + b;
}
