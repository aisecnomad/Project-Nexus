using Microsoft.Extensions.AI;

class App
{
    async System.Threading.Tasks.Task Run(IChatClient inner, AIFunction weather)
    {
        var client = new FunctionInvokingChatClient(inner);
        var options = new ChatOptions { Tools = [weather] };
        await client.GetResponseAsync("weather", options);
    }
}
