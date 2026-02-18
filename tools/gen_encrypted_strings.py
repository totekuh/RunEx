#!/usr/bin/env python3
"""Offline encryption tool for RunEx DInvoke string obfuscation.

Implements the Weyl-sequence avalanche mixer cipher and generates
C# encrypted byte arrays + keys for all DLL and API function names.

Usage: python3 tools/gen_encrypted_strings.py
"""

import random
import sys


def encrypt(plaintext: str, key: int) -> bytes:
    """Encrypt an ASCII string using the Weyl-sequence avalanche mixer."""
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
    """Verify decryption matches the original string."""
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
    """Format bytes as C# byte array literal."""
    return "new byte[] { " + ", ".join(f"0x{b:02X}" for b in data) + " }"


def fmt_key(key: int) -> str:
    """Format key as C# uint literal."""
    return f"0x{key:08X}u"


def rand_key() -> int:
    return random.randint(0, 0xFFFFFFFF)


# ── DLL names ────────────────────────────────────────────────────────
DLLS = [
    ("_ek32",  "_kk32",  "kernel32.dll"),
    ("_eadv",  "_kadv",  "advapi32.dll"),
    ("_eu32",  "_ku32",  "user32.dll"),
    ("_euenv", "_kuenv", "userenv.dll"),
    ("_ews2",  "_kws2",  "ws2_32.dll"),
]

# ── All GetDelegate call sites ───────────────────────────────────────
# (field, delegate_type, dll_index, win32_function_name)
WRAPPERS = [
    # kernel32 (dll_index=0)
    ("_CloseHandle", "CloseHandle_t", 0, "CloseHandle"),
    ("_WaitForSingleObject", "WaitForSingleObject_t", 0, "WaitForSingleObject"),
    ("_ResumeThread", "ResumeThread_t", 0, "ResumeThread"),
    ("_CreateProcess", "CreateProcess_t", 0, "CreateProcessW"),
    ("_CreatePipe", "CreatePipe_t", 0, "CreatePipe"),
    ("_SetNamedPipeHandleState", "SetNamedPipeHandleState_t", 0, "SetNamedPipeHandleState"),
    ("_ReadFile", "ReadFile_t", 0, "ReadFile"),
    ("_DuplicateHandle", "DuplicateHandle_t", 0, "DuplicateHandle"),
    ("_GetStdHandle", "GetStdHandle_t", 0, "GetStdHandle"),
    ("_GetExitCodeProcess", "GetExitCodeProcess_t", 0, "GetExitCodeProcess"),
    # advapi32 (dll_index=1)
    ("_ImpersonateLoggedOnUser", "ImpersonateLoggedOnUser_t", 1, "ImpersonateLoggedOnUser"),
    ("_SetThreadToken", "SetThreadToken_t", 1, "SetThreadToken"),
    ("_RevertToSelf", "RevertToSelf_t", 1, "RevertToSelf"),
    ("_LogonUser", "LogonUser_t", 1, "LogonUserA"),
    ("_DuplicateTokenEx", "DuplicateTokenEx_t", 1, "DuplicateTokenEx"),
    ("_OpenProcessToken", "OpenProcessToken_t", 1, "OpenProcessToken"),
    ("_CreateProcessWithLogonW", "CreateProcessWithLogonW_t", 1, "CreateProcessWithLogonW"),
    ("_CreateProcessAsUser", "CreateProcessAsUser_t", 1, "CreateProcessAsUserW"),
    ("_CreateProcessWithTokenW", "CreateProcessWithTokenW_t", 1, "CreateProcessWithTokenW"),
    ("_SetSecurityInfo", "SetSecurityInfo_t", 1, "SetSecurityInfo"),
    ("_FreeSid", "FreeSid_t", 1, "FreeSid"),
    ("_GetSecurityDescriptorDacl", "GetSecurityDescriptorDacl_t", 1, "GetSecurityDescriptorDacl"),
    ("_GetAclInformation", "GetAclInformation_t", 1, "GetAclInformation"),
    ("_InitializeSecurityDescriptor", "InitializeSecurityDescriptor_t", 1, "InitializeSecurityDescriptor"),
    ("_GetLengthSid", "GetLengthSid_t", 1, "GetLengthSid"),
    ("_InitializeAcl", "InitializeAcl_t", 1, "InitializeAcl"),
    ("_GetAce", "GetAce_t", 1, "GetAce"),
    ("_AddAce", "AddAce_t", 1, "AddAce"),
    ("_SetSecurityDescriptorDacl", "SetSecurityDescriptorDacl_t", 1, "SetSecurityDescriptorDacl"),
    ("_CopySid", "CopySid_t", 1, "CopySid"),
    ("_LookupAccountName", "LookupAccountName_t", 1, "LookupAccountNameW"),
    ("_GetTokenInformation_uint", "GetTokenInformation_uint_t", 1, "GetTokenInformation"),
    ("_GetTokenInformation_int", "GetTokenInformation_int_t", 1, "GetTokenInformation"),
    ("_LookupPrivilegeName", "LookupPrivilegeName_t", 1, "LookupPrivilegeNameW"),
    ("_AllocateAndInitializeSid", "AllocateAndInitializeSid_t", 1, "AllocateAndInitializeSid"),
    ("_SetTokenInformation", "SetTokenInformation_t", 1, "SetTokenInformation"),
    ("_GetSidSubAuthority", "GetSidSubAuthority_t", 1, "GetSidSubAuthority"),
    ("_GetSidSubAuthorityCount", "GetSidSubAuthorityCount_t", 1, "GetSidSubAuthorityCount"),
    ("_AdjustTokenPrivileges", "AdjustTokenPrivileges_t", 1, "AdjustTokenPrivileges"),
    ("_LookupPrivilegeValue", "LookupPrivilegeValue_t", 1, "LookupPrivilegeValueA"),
    # user32 (dll_index=2)
    ("_GetProcessWindowStation", "GetProcessWindowStation_t", 2, "GetProcessWindowStation"),
    ("_GetUserObjectInformation", "GetUserObjectInformation_t", 2, "GetUserObjectInformationA"),
    ("_OpenWindowStation", "OpenWindowStation_t", 2, "OpenWindowStationW"),
    ("_OpenDesktop", "OpenDesktop_t", 2, "OpenDesktopA"),
    ("_CloseWindowStation", "CloseWindowStation_t", 2, "CloseWindowStation"),
    ("_CloseDesktop", "CloseDesktop_t", 2, "CloseDesktop"),
    ("_SetProcessWindowStation", "SetProcessWindowStation_t", 2, "SetProcessWindowStation"),
    ("_GetUserObjectSecurity", "GetUserObjectSecurity_t", 2, "GetUserObjectSecurity"),
    ("_SetUserObjectSecurity", "SetUserObjectSecurity_t", 2, "SetUserObjectSecurity"),
    # userenv (dll_index=3)
    ("_CreateEnvironmentBlock", "CreateEnvironmentBlock_t", 3, "CreateEnvironmentBlock"),
    ("_DestroyEnvironmentBlock", "DestroyEnvironmentBlock_t", 3, "DestroyEnvironmentBlock"),
    ("_GetUserProfileDirectory", "GetUserProfileDirectory_t", 3, "GetUserProfileDirectoryW"),
    ("_LoadUserProfile", "LoadUserProfile_t", 3, "LoadUserProfileW"),
    ("_UnloadUserProfile", "UnloadUserProfile_t", 3, "UnloadUserProfile"),
    # ws2_32 (dll_index=4)
    ("_WSASocket", "WSASocket_t", 4, "WSASocketA"),
    ("_connect", "connect_t", 4, "connect"),
    ("_htons", "htons_t", 4, "htons"),
    ("_WSAGetLastError", "WSAGetLastError_t", 4, "WSAGetLastError"),
    ("_WSAStartup", "WSAStartup_t", 4, "WSAStartup"),
    ("_closesocket", "closesocket_t", 4, "closesocket"),
]


def main():
    random.seed()  # OS entropy

    # ── DLL constants ────────────────────────────────────────────────
    print("    // Encrypted DLL names")
    dll_enc_names = []
    dll_key_names = []
    for enc_name, key_name, dll_str in DLLS:
        key = rand_key()
        enc = encrypt(dll_str, key)
        assert decrypt(enc, key) == dll_str, f"roundtrip failed: {dll_str}"
        dll_enc_names.append(enc_name)
        dll_key_names.append(key_name)
        print(f"    private static readonly byte[] {enc_name} = {fmt_bytes(enc)};")
        print(f"    private const uint {key_name} = {fmt_key(key)};")

    print()

    # ── Per-wrapper GetDelegate replacement lines ────────────────────
    for field, dtype, dll_idx, func in WRAPPERS:
        key = rand_key()
        enc = encrypt(func, key)
        assert decrypt(enc, key) == func, f"roundtrip failed: {func}"
        de = dll_enc_names[dll_idx]
        dk = dll_key_names[dll_idx]
        print(f"        if ({field} == null) {field} = GetDelegate<{dtype}>(")
        print(f"            {de}, {dk}, {fmt_bytes(enc)}, {fmt_key(key)});")

    # Summary
    n_dlls = len(DLLS)
    n_funcs = len(WRAPPERS)
    print(f"\n// Total: {n_dlls} DLL names + {n_funcs} function names = {n_dlls + n_funcs} encrypted strings",
          file=sys.stderr)


if __name__ == "__main__":
    main()
