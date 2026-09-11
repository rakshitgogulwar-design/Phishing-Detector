from mangum import Mangum
from app.backend.main import app

# Netlify Serverless Function Handler
handler = Mangum(app, lifespan="off")
