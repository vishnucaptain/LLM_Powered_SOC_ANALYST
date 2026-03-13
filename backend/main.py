from fastapi import FastAPI
from backend.models import LogRequest
from backend.llm_agent import investigate_logs

app = FastAPI(title="LLM Powered SOC Analyst")


@app.get("/")
def health_check():
    return {"status": "SOC Analyst API running"}


@app.post("/investigate")
def investigate(request: LogRequest):

    report = investigate_logs(request.logs)

    return {
        "logs": request.logs,
        "investigation": report
    }