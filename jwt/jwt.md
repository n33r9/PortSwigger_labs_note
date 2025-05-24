# [JWT - JSON Web Token](https://portswigger.net/web-security/jwt)

About JWT:

<img src="C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250524112213349.png" alt="image-20250524112213349" style="zoom:67%;" />

![image-20250524112240677](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250524112240677.png)

![image-20250524112300295](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250524112300295.png)

![image-20250524112319269](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250524112319269.png)

Causes and Conditions: 

- Weak or guessable signing secrets (e.g., using "123456").
- Use of none algorithm (if supported) to bypass signature verification.

- Algorithm confusion attacks (e.g., changing alg from RS256 to HS256).

- Token expiration not properly enforced.


Impact: 

- Unauthorized access to protected resources.

- User impersonation or privilege escalation.

- Data leakage or account takeover.


Categories: 

- 

Prevention:  

- Always use strong, unpredictable secrets.
- Never accept unsigned (alg: none) tokens.
- Validate tokens using the correct algorithm.
- Enforce token expiration (exp claim) and proper access control checks.
- Use libraries that strictly follow JWT specifications.

Common Payloads through Labs Completion:

## - Apprentice

### [Lab 1: JWT authentication bypass via unverified signature](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)

- !the server doesn't verify the signature of any JWTs that it receives

  

## - Practitioner

