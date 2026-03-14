import { Agent } from "@openai/agents";

const triage = new Agent({
  name: "triage_agent",
  tools: ["ticket.write", "search.read"],
  dataSources: ["crm.records"],
  auth: [process.env.OPENAI_API_KEY],
});
