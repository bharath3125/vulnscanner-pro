from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from app.api.scan import router as scan_router

app = FastAPI(
    title="Web Vulnerability Scanner",
    description="An ethical web vulnerability scanner for educational purposes.",
    version="1.0.0"
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

app.include_router(scan_router, prefix="/api")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def read_report(request: Request, scan_id: str):
    return templates.TemplateResponse("report.html", {"request": request, "scan_id": scan_id})
