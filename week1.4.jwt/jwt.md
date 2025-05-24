# [JWT - JSON Web Token](https://portswigger.net/web-security/jwt)

About JWT: A JWT consists of 3 parts: a header, a payload, and a signature

![image-20250524112213349](./image/image-20250524112213349.png)

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

### [Lab 2 : JWT authentication bypass via flawed signature verification](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification)

Do the same steps with the [Lab 1](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)

- Then, try to modify `alg` field to `none`, `sub` to `administrator`
- Delete the signature part of jwt.
- change path to /admin

![image-20250524123609208](./image/image-20250524123609208.png)

![image-20250524123726811](./image/image-20250524123726811.png)

## - Practitioner

### [Lab 1: JWT authentication bypass via weak signing key](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key)

Extensions BSp: [jwt-editor](https://github.com/portswigger/jwt-editor)

attack vector: brute-force the website's secret key => sign a modify session token => access to the admin panel => delete `carlos`

[wordlist jwt serects](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)

![image-20250524125940054](./image/image-20250524125940054.png)

Do the same steps with Lab 1 and Lab 2 - apprentice: but get the result `Unauthorized`

**Part 1: Bruteforce the secret key using [Hashcat](https://hashcat.net/hashcat/)**

cookie session: 

```
eyJraWQiOiIwNDU1OGZkYi05NTc5LTRkNzctOGEyMC0xNTA0ZGNhYWIxOWUiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0ODA2OTg0NCwic3ViIjoid2llbmVyIn0.RDMyKegw29fOUGj2HNMBXHAwg81M3HEn2mKy394h16M
```

`hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list`

![image-20250524130941704](./image/image-20250524130941704.png)

Secret key is: `secret1`

**Part 2: Generate a forged signing key**

Burp encode secret key:

![image-20250524131250340](./image/image-20250524131250340.png)

Replace the above value to the `k` field below, we have:

![image-20250524131454560](./image/image-20250524131454560.png)

Save the key:

![image-20250524131626825](./image/image-20250524131626825.png)

**Part 3: Modify and sign the JWT**

![image-20250524131841516](./image/image-20250524131841516.png)

Modify the `sub` field into `administrator`. Click sign to sign with the above key: 

![image-20250524132055058](./image/image-20250524132055058.png)

Then send the req, login succesfully as `admin`, send the req to delete `carlos` user:

![image-20250524132527932](./image/image-20250524132527932.png)
