from crewai import Agent


def build_agent():
    return Agent(role="triage", goal="summarize repository state")
