from crewai import Agent
import os

researcher = Agent(
    role="research_agent",
    tools=["search.read"],
    data_sources=["warehouse.events"],
    auth_surfaces=[os.getenv("OPENAI_API_KEY")],
)

publisher = Agent(
    role="publisher_agent",
    tools=["deploy.write"],
    data_sources=["prod-db"],
    auth_surfaces=[os.getenv("GITHUB_TOKEN")],
)
