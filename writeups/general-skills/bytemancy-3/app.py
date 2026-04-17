import os
import random
import select
import sys
from typing import Optional
from pwn import ELF, p32

BANNER = "⊹──────[ BYTEMANCY-3 ]──────⊹"
BINARY_PATH = os.path.join(os.path.dirname(__file__), "spellbook")
QUESTION_COUNT = 3

SPELLBOOK_FUNCTIONS = [
    "ember_sigil",
    "glyph_conflux",
    "astral_spark",
    "binding_word",
]


def read_exact_bytes(expected_len: int) -> Optional[bytes]:
    """Read a fixed number of bytes from stdin, trimming a trailing newline."""
    stdin_buffer = sys.stdin.buffer
    buf = stdin_buffer.read(expected_len)
    if not buf or len(buf) < expected_len:
        return None

    # Discard trailing newlines only if more bytes are immediately available
    try:
        stdin_fileno = sys.stdin.fileno()
    except (AttributeError, ValueError, OSError):
        stdin_fileno = None

    if stdin_fileno is not None:
        while True:
            readable, _, _ = select.select([stdin_fileno], [], [], 0)
            if not readable:
                break

            peek = stdin_buffer.peek(1)[:1]
            if peek in (b"\n", b"\r"):
                stdin_buffer.read(1)
                continue
            break

    return buf


def main():
    try:
        elf = ELF(BINARY_PATH, checksec=False)
    except FileNotFoundError:
        print("The spellbook is missing!")
        return

    flag = open("./flag.txt", "r").read().strip()

    while True:
        try:
            print(BANNER)
            print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
            print()
            print("I will name four procedures hidden inside spellbook.")
            print(
                f"Each round, send me their *raw* 4-byte addresses "
                f"in little-endian form. {QUESTION_COUNT} correct answers unlock the flag."
            )
            print()
            print("☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐☉⟊☽☈⟁⧋⟡☍⟐")
            print('⊹─────────────⟡─────────────⊹')

            selections = random.sample(SPELLBOOK_FUNCTIONS, QUESTION_COUNT)
            success = True

            for idx, symbol in enumerate(selections, 1):
                target_addr = elf.symbols[symbol]
                expected_bytes = p32(target_addr)

                print(
                    f"[{idx}/{QUESTION_COUNT}] Send the 4-byte little-endian "
                    f"address for procedure '{symbol}'."
                )
                print("==> ", end='', flush=True)
                user_bytes = read_exact_bytes(len(expected_bytes))

                if user_bytes is None:
                    print("\nI needed four bytes, traveler.")
                    success = False
                    break

                if user_bytes != expected_bytes:
                    print("\nThose aren't the right runes.")
                    success = False
                    break

            if success:
                print(flag)
                break

            print()
            print("The aether rejects your incantation. Try again.\n")
        except EOFError:
            break
        except Exception as exc:
            print(exc)
            break


if __name__ == "__main__":
    main()
