# pyrefly: ignore [missing-import]
from fastapi import FastAPI
from cloudsim.api.routes import auth, objects, admin

app = FastAPI(title="CloudSim API", version="0.1.0")

# Register routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(objects.router, prefix="/objects", tags=["Objects"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])

@app.get("/")
def root():
    return {"message": "CloudSim API is running. Go to /docs for Swagger UI."}