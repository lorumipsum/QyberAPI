import os, time, requests
from functools import lru_cache
from flask import Flask, request, jsonify
from flask_cors import CORS
from jose import jwt

# set these in App Runner env vars
REGION        = os.environ["COGNITO_REGION"]
USER_POOL_ID  = os.environ["COGNITO_USER_POOL_ID"]
APP_CLIENT_ID = os.environ["COGNITO_APP_CLIENT_ID"]

ISSUER   = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
ALGS = ["RS256"]

app = Flask(__name__)
CORS(app, supports_credentials=True)

@lru_cache(maxsize=1)
def get_jwks():
    r = requests.get(JWKS_URL, timeout=5)
    r.raise_for_status()
    return r.json()["keys"]

def verify_id_token(token: str):
    hdr = jwt.get_unverified_header(token)
    kid = hdr.get("kid")
    key = next((k for k in get_jwks() if k.get("kid") == kid), None)
    if not key:
        raise jwt.JWTError("No matching JWK")
    public_key = {"kty": key["kty"], "e": key["e"], "n": key["n"], "alg": key.get("alg","RS256")}
    return jwt.decode(
        token,
        public_key,
        algorithms=ALGS,
        audience=APP_CLIENT_ID,
        issuer=ISSUER,
        options={"verify_at_hash": False}
    )

@app.get("/health")
def health():
    return {"ok": True, "ts": int(time.time())}

@app.get("/api/me")
def me():
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "):
        return jsonify({"error":"missing_bearer"}), 401
    token = auth.split(" ",1)[1]
    try:
        claims = verify_id_token(token)
        return {
            "sub": claims.get("sub"),
            "email": claims.get("email"),
            "groups": claims.get("cognito:groups", []),
            "claims": claims
        }
    except Exception as e:
        return jsonify({"error":"invalid_token","detail":str(e)}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
