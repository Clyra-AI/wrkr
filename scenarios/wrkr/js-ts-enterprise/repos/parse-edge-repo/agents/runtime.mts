import { Agent } from "@openai/agents";

const runtime_agent = new Agent({
  name: "runtime_agent",
  tools: ["search.read"],
});
