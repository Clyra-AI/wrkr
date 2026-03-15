# wrkr:custom-agent name=triage_agent tools=search.read,ticket.write data=crm.records auth=OPENAI_API_KEY
triage = build_agent()

# wrkr:custom-agent name=release_agent tools=deploy.write auth=GITHUB_TOKEN deploy=.github/workflows/release.yml auto_deploy=true human_gate=true
release = build_agent()
