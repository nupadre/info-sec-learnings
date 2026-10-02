# Understanding Path Traversal Vulnerabilities

**Path traversal**, frequently referred to as **directory traversal**, is a critical web security vulnerability. It occurs when an application fails to properly sanitize user-supplied input that is used to construct a file path. This oversight allows an attacker to manipulate the file path and access files or directories that reside outside the web root folder.

In the OWASP Top 10, Path Traversal falls broadly under the category of **Broken Access Control**, as it allows attackers to bypass intended directory restrictions.

## The Impact of Path Traversal

When an attacker successfully exploits a path traversal vulnerability, they can read arbitrary files on the server hosting the application. This unauthorized access can lead to severe data breaches and system compromise. Attackers typically target:

* **Application Code and Data:** Accessing source code, configuration files, and internal application logic.
* **Back-end System Credentials:** Uncovering passwords, API keys, and database connection strings used by the application (e.g., `.env` files).
* **Sensitive Operating System Files:** Reading core system files that reveal user accounts, network configurations, and system architecture.

**Escalation to Server Takeover:** In certain scenarios, path traversal isn't limited to just *reading* files. If the application allows file uploads or modifications and is vulnerable to path traversal, an attacker might be able to *write* to arbitrary files. This can allow them to overwrite critical system files (like SSH authorized keys), modify application behavior, and ultimately achieve full remote code execution (RCE).

## How Path Traversal Works: A Practical Scenario

To understand how this vulnerability is exploited, consider a typical e-commerce shopping application that displays product images.

### 1. Normal Application Behavior

The application loads images dynamically using an HTML `<img>` tag that references a specific endpoint and passes a filename parameter:

```html
<img src="/loadImage?filename=218.png">
```

Behind the scenes, the `loadImage` URL receives the `filename` parameter (`218.png`) and fetches it from a designated storage directory on the server's disk, such as `/var/www/images/`.

The application appends the user-supplied filename to the base directory and uses a standard filesystem API to read the file. The intended file path looks like this:

```text
/var/www/images/218.png
```

### 2. The Exploit (Reading Arbitrary Files)

If the application does not validate or sanitize the `filename` parameter, it assumes the user input is safe. An attacker can exploit this trust by supplying special characters—specifically the "dot-dot-slash" sequence (`../`)—to manipulate the path.

The `../` sequence is a standard directive in file systems that means "step up one directory level."

An attacker could modify the URL request to look like this:

```text
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```

When the application processes this input, it constructs the following file path:

```text
/var/www/images/../../../etc/passwd
```

**How the filesystem resolves this:**
1. Start at `/var/www/images/`
2. `../` moves up to `/var/www/`
3. `../` moves up to `/var/`
4. `../` moves up to `/` (the filesystem root)
5. `etc/passwd` navigates to the `passwd` file inside the `etc` directory.

The application, completely bypassed of its intended directory confinement, reads and returns the contents of `/etc/passwd`.

## Operating System Variations

The characters used for directory traversal depend on the underlying operating system running the web server:

* **Unix-Based Systems (Linux, macOS):** Use the forward slash (`/`) as a directory separator. The standard traversal sequence is `../`.
* **Windows Systems:** Recognize both the forward slash (`/`) and the backslash (`\`) as valid directory separators. Therefore, both `../` and `..\` are valid traversal sequences.

## Advanced Traversal Techniques (Evasion Strategies)

Defenders often implement basic filters to strip out `../` sequences. As an attacker (or a penetration tester), you must know how to bypass these naive defenses.

* **Absolute Paths:** If the application doesn't strictly append the input to a base directory, an attacker might just provide an absolute path directly, skipping the `../` entirely:
  `filename=/etc/passwd`
* **Nested Traversal Sequences:** If a developer uses a simple replace function to delete `../`, an attacker can use `....//` or `..././`. When the inner `../` is deleted, the remaining characters form a new `../`:
  `filename=....//....//etc/passwd`
* **URL Encoding:** Web Application Firewalls (WAFs) might block standard `../`. Attackers can use URL encoding (or double URL encoding) to bypass these filters:
  * Standard encoding: `%2e%2e%2f`
  * Double encoding: `%252e%252e%252f`
* **Null Byte Injection (`%00`):** Some older applications (especially PHP/C-based) require a specific file extension (e.g., `.png`). An attacker can append a null byte to truncate the string at the OS level, tricking the validation:
  `filename=../../../etc/passwd%00.png`

## Remediation and Prevention: Securing Your Applications

To properly defend against Path Traversal, you must adopt a defense-in-depth approach. Here is what you should implement:

1. **Avoid Direct Object References (Best Practice):** 
   The most foolproof way to prevent this is to *never* pass user-supplied input directly to filesystem APIs. Instead, use indirect references like an ID or a hash mapping. 
   *Example:* `?imageId=5` retrieves a file mapped to `5` in a database, rather than passing `?filename=image.png`.

2. **Strict Allowlisting (Input Validation):**
   If you must use user input, validate it strictly against an allowlist of permitted values or formats. Do not rely on blocklisting (trying to filter out `../`), as attackers will find ways around it. Ensure the input contains only permitted characters (e.g., purely alphanumeric).

3. **Validate the Canonical Path:**
   If you must dynamically construct file paths, you should always canonicalize the path before interacting with the file system.
   *   Use built-in framework functions (like `path.basename()` in Node.js, `basename()` in PHP, or `Path.GetFileName()` in C#) to extract *only* the filename, discarding any directory paths.
   *   Append this secure filename to your base directory.
   *   **Crucial Step:** Resolve the absolute path and verify that it strictly starts with your expected base directory.

   *Example (Conceptual Java):*
   ```java
   File file = new File(BASE_DIRECTORY, userInput);
   if (!file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
       throw new SecurityException("Path traversal attempt detected!");
   }
   ```

4. **Principle of Least Privilege:**
   Ensure the web server process runs with the absolute minimum privileges necessary. It should only have read access to the specific directories required for the application to function, and write access only where explicitly needed. It should never have read access to sensitive OS directories like `/etc` or `C:\Windows`. Consider running the application in a restricted environment like a `chroot` jail or a Docker container.