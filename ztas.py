from fastapi import FastAPI, Header, HTTPException
import secrets
import time

app = FastAPI(title="Zero Trust Auth System")

# In-memory token store (demo purpose)
TOKENS = {}

TOKEN_EXPIRY_SECONDS = 300  # 5 minutes

def generate_token():
    return secrets.token_hex(16)

def verify_token(token: str):
    data = TOKENS.get(token)
    if not data:
        return False
    if time.time() > data["expires"]:
        del TOKENS[token]
        return False
    return True

@app.post("/login")
def login(username: str):
    token = generate_token()
    TOKENS[token] = {
        "user": username,
        "expires": time.time() + TOKEN_EXPIRY_SECONDS
    }
    return {
        "message": "Authenticated",
        "token": token,
        "expires_in_seconds": TOKEN_EXPIRY_SECONDS
    }

@app.get("/secure-data")
def secure_data(authorization: str = Header(None)):
    if not authorization or not verify_token(authorization):
        raise HTTPException(status_code=401, detail="Access denied")

    return {
        "data": "Sensitive information",
        "trust": "verified per request"
    }

@app.get("/health")
def health():
    return {"status": "running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
