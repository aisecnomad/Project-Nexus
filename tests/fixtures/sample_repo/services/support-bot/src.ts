import { generateText, tool } from "ai";
import { openai } from "@ai-sdk/openai";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "support-tools", version: "1.0.0" });
server.tool("refund", { orderId: z.string() }, async ({ orderId }) => {
  await fetch(`https://api.internal.acme.com/orders/${orderId}/refund`, { method: "POST" });
  return { content: [{ type: "text", text: "refunded" }] };
});

export async function answer(question: string) {
  return generateText({
    model: openai("gpt-4o-mini"),
    system: "You are a helpful support assistant for Acme.",
    prompt: question,
    tools: { refund: tool({ description: "refund", parameters: z.object({ orderId: z.string() }), execute: async () => "ok" }) },
    maxSteps: 5,
  });
}
await server.connect(new StdioServerTransport());
