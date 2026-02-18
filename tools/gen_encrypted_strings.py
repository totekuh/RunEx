#!/usr/bin/env python3
"""Transform DInvoke.cs.in (plaintext) into DInvoke.cs (encrypted strings).

Reads the template with readable GetDelegate<T>("dll", "func") calls,
encrypts all DLL and function name strings using the Weyl-sequence
avalanche mixer, and writes the final C# source to stdout.

Usage: python3 tools/gen_encrypted_strings.py src/DInvoke.cs.in > src/DInvoke.cs
"""

import re
import random
import sys


def encrypt(plaintext: str, key: int) -> bytes:
    data = plaintext.encode('ascii')
    result = bytearray(len(data))
    k = key & 0xFFFFFFFF
    for i in range(len(data)):
        k = (k + 0x6D2B79F5) & 0xFFFFFFFF
        t = k
        t = ((t ^ (t >> 15)) * 0x2C1B3C6D) & 0xFFFFFFFF
        t = ((t ^ (t >> 12)) * 0x297A2D39) & 0xFFFFFFFF
        t = (t ^ (t >> 15)) & 0xFFFFFFFF
        shift = (i & 3) << 3
        b = (t >> shift) & 0xFF
        result[i] = data[i] ^ b
    return bytes(result)


def decrypt(encrypted: bytes, key: int) -> str:
    result = bytearray(len(encrypted))
    k = key & 0xFFFFFFFF
    for i in range(len(encrypted)):
        k = (k + 0x6D2B79F5) & 0xFFFFFFFF
        t = k
        t = ((t ^ (t >> 15)) * 0x2C1B3C6D) & 0xFFFFFFFF
        t = ((t ^ (t >> 12)) * 0x297A2D39) & 0xFFFFFFFF
        t = (t ^ (t >> 15)) & 0xFFFFFFFF
        shift = (i & 3) << 3
        b = (t >> shift) & 0xFF
        result[i] = encrypted[i] ^ b
    return result.decode('ascii')


def fmt_bytes(data: bytes) -> str:
    return "new byte[] { " + ", ".join(f"0x{b:02X}" for b in data) + " }"


def fmt_key(key: int) -> str:
    return f"0x{key:08X}u"


def rand_key() -> int:
    return random.randint(0, 0xFFFFFFFF)


# Map DLL name -> (encrypted-field, key-field)
DLL_SHORT = {
    "kernel32.dll": ("_ek32",  "_kk32"),
    "advapi32.dll": ("_eadv",  "_kadv"),
    "user32.dll":   ("_eu32",  "_ku32"),
    "userenv.dll":  ("_euenv", "_kuenv"),
    "ws2_32.dll":   ("_ews2",  "_kws2"),
}

DECRYPT_FUNC = """\
    private static string D(byte[] e, uint k) {
        byte[] b = new byte[e.Length];
        for (int i = 0; i < e.Length; i++) {
            k += 0x6D2B79F5u;
            uint t = k;
            t = (t ^ (t >> 15)) * 0x2C1B3C6Du;
            t = (t ^ (t >> 12)) * 0x297A2D39u;
            t ^= t >> 15;
            b[i] = (byte)(e[i] ^ (byte)(t >> ((i & 3) << 3)));
        }
        return System.Text.Encoding.ASCII.GetString(b);
    }"""

GETDELEGATE_ENCRYPTED = """\
    private static T GetDelegate<T>(byte[] dllEnc, uint dllKey, byte[] funcEnc, uint funcKey) where T : class
    {
        string dll = D(dllEnc, dllKey);
        string func = D(funcEnc, funcKey);
        IntPtr mod = GetModuleHandle(dll);
        if (mod == IntPtr.Zero) mod = LoadLibrary(dll);
        IntPtr addr = GetProcAddress(mod, func);
        return (T)(object)Marshal.GetDelegateForFunctionPointer(addr, typeof(T));
    }"""


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input.cs.in>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], 'r') as f:
        source = f.read()

    # --- Step 1: Collect unique DLL names and generate encrypted constants ---
    call_re = re.compile(r'GetDelegate<\w+>\("([^"]+)",\s*"[^"]+"\)')
    dll_names = sorted(set(m.group(1) for m in call_re.finditer(source)))

    for d in dll_names:
        if d not in DLL_SHORT:
            print(f"ERROR: Unknown DLL '{d}' — add it to DLL_SHORT", file=sys.stderr)
            sys.exit(1)

    dll_constants = ["    // Encrypted DLL names"]
    dll_encrypted = {}  # dll_name -> (enc_field, key_field)
    for d in dll_names:
        enc_field, key_field = DLL_SHORT[d]
        key = rand_key()
        enc = encrypt(d, key)
        assert decrypt(enc, key) == d
        dll_encrypted[d] = (enc_field, key_field)
        dll_constants.append(f"    private static readonly byte[] {enc_field} = {fmt_bytes(enc)};")
        dll_constants.append(f"    private const uint {key_field} = {fmt_key(key)};")
    dll_block = "\n".join(dll_constants)

    # --- Step 2: Replace the plaintext GetDelegate<T> method definition ---
    getdelegate_re = re.compile(
        r'    private static T GetDelegate<T>\(string dll, string func\) where T : class\s*\{[^}]+\}',
        re.DOTALL
    )
    replacement = DECRYPT_FUNC + "\n\n" + GETDELEGATE_ENCRYPTED + "\n\n" + dll_block
    source = getdelegate_re.sub(replacement, source)

    # --- Step 3: Replace every GetDelegate<Type>("dll", "func") call site ---
    call_count = [0]

    def replace_call(match):
        call_count[0] += 1
        delegate_type = match.group(1)
        dll = match.group(2)
        func = match.group(3)
        enc_field, key_field = dll_encrypted[dll]
        fk = rand_key()
        fe = encrypt(func, fk)
        assert decrypt(fe, fk) == func
        return (f"GetDelegate<{delegate_type}>(\n"
                f"            {enc_field}, {key_field}, {fmt_bytes(fe)}, {fmt_key(fk)})")

    call_site_re = re.compile(r'GetDelegate<(\w+)>\("([^"]+)",\s*"([^"]+)"\)')
    source = call_site_re.sub(replace_call, source)

    sys.stdout.write(source)
    print(f"Encrypted {len(dll_names)} DLLs + {call_count[0]} call sites", file=sys.stderr)


if __name__ == "__main__":
    main()
