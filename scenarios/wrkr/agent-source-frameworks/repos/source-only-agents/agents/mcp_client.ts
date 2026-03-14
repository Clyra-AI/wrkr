import { Client } from "@modelcontextprotocol/sdk/client";

const prodClient = new Client({
  name: "prod_client",
  servers: ["postgres-prod", "redis-prod"],
  auth: [process.env.MCP_API_TOKEN],
});
