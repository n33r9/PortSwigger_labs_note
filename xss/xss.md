Các nội dung của tuần này nhé mn:

- SQL Injection
- XSS
- CSRF
- JWT attack
  Out put là hoàn thành các labs mức APPRENTICE, PRACTITIONER.
  Mỗi dạng này cần có report về nguyên nhân, tác động, phân loại của lỗ hổng, các payload tấn công phổ biến, khuyến nghị cách khắc phục.

# [XSS](https://portswigger.net/web-security/cross-site-scripting)

Causes: 

- 

Impact: 

Categories: 

- [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting#reflected-cross-site-scripting): the **malicious script** comes from the **current HTTP request**.
- [Stored XSS](https://portswigger.net/web-security/cross-site-scripting#stored-cross-site-scripting): the **malicious script** comes from the **website's database**.
- [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting#dom-based-cross-site-scripting), where the vulnerability exists in client-side code rather than server-side code.

Prevention:  

Common Payloads through Labs Completion:

## - Apprentice

### [Lab 1: Lab: Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)

![image-20250522212411441](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250522212411441.png)

### [Lab 2: Stored XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)

- Malicious scripts saved in database

![image-20250523152242337](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250523152242337.png)

![image-20250523152511060](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250523152511060.png)

### [Lab 3: DOM XSS in `document.write` sink using source `location.search`](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)

- Inspect the search query:
- ![image-20250523165323032](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250523165323032.png)

`<img src="/resources/images/tracker.gif?searchTerms=">`

- Break the img src tag, using query search: `"><svg onload=alert(1)>`

![image-20250523172924769](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250523172924769.png)



## - Practitioner

### [Lab 1: DOM XSS in `document.write` sink using source `location.search` inside a select element](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element)



![image-20250524002349658](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250524002349658.png)

![image-20250524002537932](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250524002537932.png)

- add query `storeId` into the URL:

![image-20250524002815357](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250524002815357.png)

- Add xss payload to the URL:

![image-20250524003148677](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250524003148677.png)

![image-20250524003624020](C:\Users\n33r9\AppData\Roaming\Typora\typora-user-images\image-20250524003624020.png)