import { Agent } from "@openai/agents";

const release_agent = new Agent({
  name: "release_agent",
  tools: ["deploy.write"],
  auth: [process.env.OPENAI_API_KEY],
});
