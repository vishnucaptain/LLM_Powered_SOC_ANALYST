from backend.llm_agent import investigate_logs
print("Output from investigate_logs:")
print(investigate_logs('test error user login failure', event_sequence=['LOGIN_FAILED']))
