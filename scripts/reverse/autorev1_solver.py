#!/usr/bin/env python3
import re
import socket
import sys
from typing import Optional

PROMPT = b"What's the secret?"


def extract_secret_from_hex(blob: str) -> int:
    """
    Find the immediate 32-bit constant in the emitted ELF hex.

    Typical pattern in these Autorev 1 binaries:
        c7 45 fc <imm32_le>
    which corresponds to:
        movl $IMM32, -0x4(%rbp)

    The program then reads input with scanf("%u", ...), so we must reply
    with the decimal representation of that unsigned 32-bit integer.
    """
    hex_text = re.sub(r"[^0-9a-fA-F]", "", blob).lower()

    # Most specific pattern first: the challenge binaries consistently use
    #   c745fc <imm32> c745f8 00000000
    m = re.search(r"c745fc([0-9a-f]{8})c745f800000000", hex_text)
    if not m:
        # Fallback: look for any movl imm32, -0x4(%rbp)
        matches = re.findall(r"c745fc([0-9a-f]{8})", hex_text)
        if not matches:
            raise ValueError("Could not find the secret constant pattern.")
        imm_le = matches[-1]
    else:
        imm_le = m.group(1)

    imm_bytes = bytes.fromhex(imm_le)
    secret = int.from_bytes(imm_bytes, byteorder="little", signed=False)
    return secret


def recv_until_prompt(sock: socket.socket) -> bytes:
    data = b""
    while PROMPT not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


def solve_round(text: str) -> Optional[int]:
    if "What's the secret?" not in text:
        return None
    return extract_secret_from_hex(text)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        print(f"Example: {sys.argv[0]} mysterious-sea.picoctf.net 52183")
        return 1

    host = sys.argv[1]
    port = int(sys.argv[2])

    with socket.create_connection((host, port)) as sock:
        sock.settimeout(10)
        round_no = 1

        while True:
            try:
                raw = recv_until_prompt(sock)
            except socket.timeout:
                print("[!] Timed out while waiting for data.")
                return 2

            if not raw:
                print("[!] Connection closed.")
                return 3

            text = raw.decode(errors="ignore")
            print(f"\n===== Round {round_no} =====")

            # Show a short tail so you can see progress without flooding output.
            tail = text[-3000:]
            print(tail)

            answer = solve_round(text)
            if answer is None:
                # Probably reached the flag / final output.
                print("\n[+] Final server output:")
                print(text)
                return 0

            print(f"[+] Secret = {answer}")
            sock.sendall(f"{answer}\n".encode())

            try:
                reply = sock.recv(4096)
            except socket.timeout:
                print("[!] Timed out after sending answer.")
                return 4

            if not reply:
                print("[!] Connection closed after answer.")
                return 5

            reply_text = reply.decode(errors="ignore")
            print(reply_text)

            if "Correct!" not in reply_text and "What's the secret?" not in reply_text:
                # If the next prompt didn't come in the same packet, continue the loop.
                # But if we already got a failure message, surface it.
                if "Nice try" in reply_text or "Nope" in reply_text:
                    print("[!] Server rejected the answer.")
                    return 6

            # If the server already included the next round in this same reply, we could
            # process it, but the simple loop is enough for these challenge instances.
            round_no += 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
