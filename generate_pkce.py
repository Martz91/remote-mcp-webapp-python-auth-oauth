import secrets
import base64
import hashlib

# Generate PKCE code verifier and challenge
code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')

print(f"Code Verifier: {code_verifier}")
print(f"Code Challenge: {code_challenge}")
