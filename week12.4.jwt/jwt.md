# [JWT - JSON Web Token](https://portswigger.net/web-security/jwt)

- JSON: 

  ```json
  {
  "4afadf00acff2e0bd29a11ebfdaef56d": {
  "extensions": ["log", "asm", "dot"],
  "status": "success"
  },
  "4b190749eec02de25e9f2f0617540a4c": {
  "extensions": ["log"],
  "status": "error"
  },
  "8c139876f8cfab51c14385e6f0d293bc": {
  "extensions": ["asm", "dot"],
  "status": "success"
  }
  }
  ```

  

- About JWT: A JWT consists of 3 parts: a header, a payload, and a signature

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

### [Lab 2: JWT authentication bypass via jwk header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection)

The application improperly processes the JWK header (Accept the public key specified by users??): 

==> inject our own key, tricking the server into accepting a `forged token`

==> unauthorized access to protected resources or admin functionalities

- login with the given cred, observer the JWT header:

![image-20250531155146108](./image/image-20250531155146108.png)

=> Param `kid` suggest that the server might use a `jku` to save a list of valid public keys

(Maybe during the process of building the application, the programmer needs to test the program, so he has allowed the server to authenticate with the public key embedded in the JWT using the `jwk` parameter in the headers. By the time the app is used in practice, this feature may have been "forgotten" to be removed! As a result, the attacker can create a public key on his own and embed it in the `jwk` parameter)

- in Burp Repeater, change the path to `/admin` and send the request. 

  => the admin panel is only accessible when logged in as the `administrator` user.

  ![image-20250531161041634](./image/image-20250531161041634.png)

- gen RSA key: 

![image-20250531160720126](./image/image-20250531160720126.png)

Choose `attack` > `embedding JWK` > `RSA key` > `OK`: 

![image-20250531161313330](./image/image-20250531161313330.png)

Send the request, access to the admin panel, delete `carlos` user:

![image-20250531161647656](./image/image-20250531161647656.png)

 ![image-20250531161902110](./image/image-20250531161902110.png)



=> to prevent the attacking of Injecting Self-Signed JWTS via JWK parameter, we should not accept the public key designated by users.

### [Lab 3: JWT authentication bypass via jku header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)

The structure of jku is basically a JSON structure containing a lot of tokens as shown below.

```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}
```

The server uses JWTs for session management and supports the `jwk` parameter in the JWT header. The flaw here is that the server doesn't verify if the provided key is from a trusted source.

- log in with the given cred
- observe the `kid` param as in the lab 2
- attempt to log in as administrator => rejected by the server
- changing the algorithm to `none` => also failed

**Part 1: upload a malicious JWK Set to the exploit server**

- Gen a new RSA key, copy to the body tab in the exploit server and store the payload exploit. 

  ```json
  {
      "keys": [
  {
      "p": "1eIIjoUVI8B1rcwmmpuPWwroFy_u2iesFrPpe7VT6p2WgCTapTU9Mu_d2NfAlyP1qIkeBPhCAH8nPUzXzXa6cRhVJjTWhO1q3Eu0GBk9fwz6ldncYP6DVRJrtjXo1G1_udYtn-jrqs6oFIZgGopARtNHks4hWvGzW1uJc8nQxSU",
      "kty": "RSA",
      "q": "vfixOwEDKkw8SUfMtt8ByuFCo-RV1g1ojvvzOj-iRhgeMcmL-0HDdBN-AYR5taCcGiVaWW77DFDo5En0SHjkUWBhMFBaWIuyxkOp-LDo75WXl-NSh5kw7-WPcrmXPaK1ulzipKVmBj9MeJ51TW0qeUED9DNozDR8lrzaJQBiGsM",
      "d": "AmiSCxUxDvMrCiAJItwwEONfvY4jTWVfd4vFG6Nb-zft5oDUqI2xpwmIk1Bjb-5dst3quO0LN1D7Shx_AvuV4CBCUkusuak90nrtb9mnUf711ZJf6mfjl4B3w4DBR6nxLd8hpk5t9S8lhJaH07zM4yNx-WiAxk6JCfzqanEYYhe_t1Oz7EDk8vcTZKQk5A0AGZ1iIAbYmVHwXkpUVbWcOq6dgwyTQvyA2n3uxnr8Pp1lghmhUAANPhafDyeUlvtE2npUJPGq_Cqd3DRreT0v5eKWzo-ElMtuDyLCYQSkCmLm-QRGtnuP1CFX_FDfE-EDZ93mtdA8clrSoUQAeaYYNQ",
      "e": "AQAB",
      "kid": "4bbff5c6-23cd-4713-8759-9fffd07f4709",
      "qi": "Jp5WNKH35vhen_DNTsIX4K1pDy2IM-Z1_kt8rrbZCYi03xlpeSC-t-qWWPc2nhLOZWQQ59dRbdtbyN_RWS6EkPd8OwLlHNZR4AhDSd5vEIxQAx_xy6cGAHpa_LQ_ayGneNpbzwBNqn8aGTEUIxXFCTmlwj0CnmmMVGvNXn7giUE",
      "dp": "vTk9ssFg44F5W2q7WJt55-UtUp5QpeblZCyFy7Gv7WjAZty0J-eDHlaCoj63H8BrrVCqI2F0GzZjg-NBJYD-D-KkKqoig_X8TawYSB3Ef2v_IqZdR97EWHZ0nv7w30eE8eff85LBNRuiLo535eMcXMy9jM8bSXd-47uHTs5lCpU",
      "dq": "vffzQw3AHIwfvSgPjs9y-25HNZ0gOO0vocxRbe40V-PGTgM9-APLcEgNuXbAPuBdOcggkU5pvecq_R73KYG6z6WRir7PmbwZCiqfzhEa3nq5HSo1XWPTjBIDYLY2h2wuTi6UdhDv9U9XKUdMBiEkWByr14eRRKM384TmoBnCAQ",
      "n": "nrenXBYskcFx-2LJRbbf-KXwBaG_yJJvLsguLrZo6r19FjJ-v1nDLkEGyEKbTdFP_M_i3x6KUzI5K5Oo2_yd-qEAA5pTfTlmQEodScXeMDV_r710bJRFWHALUZsJgOTNXq4lsgX9EajqseME1Ml1wID-i-ZONJe0-CMcyzuL9DLzwuTXBuJtrPFhtDONP9kieiCf5g4FEZEn_5VPYv4nhKDLliE0Xbcec-xU_xw9ejZo17E8M1WRKRgFNzQED8LBYG7vwLv655LEG1hR0_kpiZktphlza49r2vmehGufAWSGU4_gW--yQyfvhI40CG4Kkf4xmWayTkjpPLf2ZjXtLw"
  }
  
      ]
  }
  ```

  **Part 2: Modify and sign the JWT**

- replace the `kid` in the request by `kid` stored in the server: 

  ![image-20250531170513904](./image/image-20250531170513904.png)

- Add a new `jku` parameter to the header of the JWT. Set its value to the URL of your JWK Set on the exploit server.

  ![image-20250531173525987](./image/image-20250531173525987.png)

- sign the JWT with the key generated: 

  ![image-20250531171649946](./image/image-20250531171649946.png) 

- Send the request and get access to the admin panel

![image-20250531173405466](./image/image-20250531173405466.png)

- Delete `carlos` user and solved the lab: 

![image-20250531173505924](./image/image-20250531173505924.png)

=> to prevent this attack technique, when decoding JWT, the server should check the parameters in JWT and make sure they comply with the rules and limits have been defined in advance. In particular, do not allow users to add JKU parameters in JWT. Examples of test function:

```js
// check and decode JWT 
function verifyAndDecodeJWT(token) {
  try {
    const decoded = jwt.verify(token, 'JWT_SECRET_KEY');

    // check the rule
    if (decoded.jku) {
      throw new Error('Invalid JWT: "jku" parameter is not allowed.');
    }

    // processing code
    // ...

    return decodd;
  } catch (error) {
    console.error('JWT verification failed:', error.message);
    return null;
  }
}

```

### [Lab 4: JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)

In addition to being used to determine public key or secret key (private key) in JWT's signature verification, KID can be appointed the path value pointing to the file containing the verification key information. 

We can target this parameter with the Director of Directory Traversal, causing the site to find arbitrary files in the server.

- Log in with the given creds

- try with /admin path => unauthorized

- Create a self-signed JWT:

  - Create a symmetric key

    - Go to the **JWT Editor Keys** tab in Burp's main tab bar.

    - Click **New Symmetric Key**.

    - In the dialog, click **Generate** to generate a new key in JWK format. Note that you don't need to select a key size as this will automatically be updated later.

    - Replace the generated value for the `k` property with a Base64-encoded null byte (`AA==`). Note that this is just a workaround because the JWT Editor extension won't allow you to sign tokens using an empty string.

      ![image-20250531191106025](./image/image-20250531191106025.png)

  - Modify and sign the jwt:

    - Go back to the `GET /admin` request in Burp Repeater and switch to the extension-generated **JSON Web Token** message editor tab.

    - In the header of the JWT, change the value of the `kid` parameter to a path traversal sequence pointing to the `/dev/null` file:

      ```
      ../../../../../../../dev/null
      ```

      ***?? How to define this path? Change to this `../../../dev/null`, get the same result***

    - In the JWT payload, change the value of the `sub` claim to `administrator`.

    - At the bottom of the tab, click **Sign**, then select the symmetric key that you generated in the previous section.

    - Make sure that the **Don't modify header** option is selected, then click **OK**. The modified token is now signed using a null byte as the secret key.

    - Send the request and observe that you have successfully accessed the admin panel.

    - In the response, find the URL for deleting `carlos` (`/admin/delete?username=carlos`). Send the request to this endpoint to solve the lab.

    ![image-20250531190314718](./image/image-20250531190314718.png)

  - Send the request: 

![image-20250531191245611](./image/image-20250531191245611.png)

=> To address the JWT authentication bypass vulnerability, ensure that the `kid` header is properly validated and sanitized to prevent path traversal attacks. Implement rigorous checks to prevent unauthorized key access and avoid using /dev/null or null bytes within the kid header to maintain robust authentication mechanisms.
