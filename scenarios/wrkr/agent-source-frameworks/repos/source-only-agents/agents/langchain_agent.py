from langchain.agents import create_react_agent
import os

planner = create_react_agent(
    llm=llm,
    tools=["search.read", "deploy.write"],
    name="planner_agent",
    data_sources=["warehouse.events"],
    auth_surfaces=[os.getenv("OPENAI_API_KEY")],
)
