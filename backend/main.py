from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.models import LogRequest
from backend.llm_agent import investigate_logs

app = FastAPI(title="LLM Powered SOC Analyst")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Chrome Private Network Access: allows file:// and non-localhost origins
# to fetch from localhost without being blocked by the browser.
@app.middleware("http")
async def add_private_network_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


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