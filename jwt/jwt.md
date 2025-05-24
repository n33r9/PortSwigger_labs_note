# [JWT - JSON Web Token](https://portswigger.net/web-security/jwt)

About JWT:

<img src="C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250524112213349.png" alt="image-20250524112213349" style="zoom:67%;" />

![image-20250524112240677](./image/image-20250524112240677.png)

![image-20250524112300295](./image/image-20250524112300295.png)

![image-20250524112319269](./image/image-20250524112319269.png)

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

![image-20250524113525897](./image/image-20250524113525897.png)

=> Session cookie: a JWT

Decode base-64 JWT in BSp:

```json
{
 "kid":"6cfbf2df-5d02-4cb3-998b-720e97a57811",
 "alg":"RS256"
}
```

```json
{
"iss":"portswigger",
"exp":1748064823,
"sub":"wiener
}
```

- send request to repeater tab, change the `sub` field into `administrator`:

![image-20250524114702325](./image/image-20250524114702325.png)

- send req GET again with `/admin` path with the `sub` field changed

![image-20250524115126834](./image/image-20250524115126834.png)

- find the URL for deleting `carlos` (`/admin/delete?username=carlos`)

![image-20250524115334555](./image/image-20250524115334555.png)

![image-20250524115637779](./image/image-20250524115637779.png)

Edit the req, send and get the result of the lab!

## - Practitioner

