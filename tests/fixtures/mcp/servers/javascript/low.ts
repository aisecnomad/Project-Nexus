import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const lowLevel = new Server({ name: "arithmetic-low", version: "1.0.0" }, { capabilities: { tools: {} } });

lowLevel.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
