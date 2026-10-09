using Microsoft.Extensions.AI;

class App
{
    static string Greet(string name) => $"Hello {name}";

    void Run()
    {
        var tool = AIFunctionFactory.Create(Greet);
        System.Console.WriteLine(tool.Name);
    }
}
