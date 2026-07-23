from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.analyzer import analyze_email
from app.database import (
    get_investigation,
    get_investigations,
    get_statistics,
    initialize_database,
    save_investigation,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Phishing Email Investigation Dashboard",
    description="Analyze suspicious emails, extract IOCs and calculate risk.",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "statistics": get_statistics(),
            "investigations": get_investigations(),
        },
    )


@app.post("/analyze")
async def analyze(raw_email: str = Form(...)):
    if not raw_email.strip():
        raise HTTPException(status_code=400, detail="Email content is required")

    result = analyze_email(raw_email)
    investigation_id = save_investigation(result)

    return RedirectResponse(
        url=f"/investigations/{investigation_id}",
        status_code=303,
    )


@app.get("/investigations/{investigation_id}", response_class=HTMLResponse)
async def investigation_details(request: Request, investigation_id: int):
    investigation = get_investigation(investigation_id)

    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return templates.TemplateResponse(
        request=request,
        name="investigation.html",
        context={"investigation": investigation},
    )


@app.get("/api/investigations")
async def investigations_api():
    return get_investigations()


@app.get("/api/investigations/{investigation_id}")
async def investigation_api(investigation_id: int):
    investigation = get_investigation(investigation_id)

    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return investigation


@app.get("/api/statistics")
async def statistics_api():
    return get_statistics()


@app.get("/api/health")
async def health():
    return {"status": "healthy"}
