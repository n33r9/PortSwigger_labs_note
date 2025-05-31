# pip install pyjwt
import jwt
import secrets

# Tạo secret key ngẫu nhiên, an toàn
secret_key = secrets.token_urlsafe(32)  # 32 bytes ~ độ dài 43 ký tự an toàn cho JWT
print("Generated secret key:", secret_key)

# Dữ liệu payload
payload = {'user_id': 'n33r9'}
algorithm = 'HS256'

# Tạo JWT
jwt_token = jwt.encode(payload, secret_key, algorithm=algorithm)
print("JWT token:", jwt_token)

# Giải mã JWT
try:
    decoded = jwt.decode(jwt_token, secret_key, algorithms=[algorithm])
    print("Decoded payload:", decoded)
except jwt.InvalidTokenError as e:
    print("Error decoding JWT:", str(e))
