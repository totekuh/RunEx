#!/usr/bin/env python3
"""Build-time identifier obfuscation for C# sources.

Copies .cs files from src_dir to build_dir with class names, delegate
types, cached fields, internal methods, and branding replaced with
random identifiers.  Original sources are never touched.

Usage: python3 tools/obfuscate.py <src_dir> <build_dir>
"""

import os
import re
import sys
import random
import string

MIN_IDENT_LEN = 3  # skip single/two-char names like D, e, k, cb, sd


def rand_id(length=11):
    first = random.choice(string.ascii_letters)
    rest = ''.join(random.choices(string.ascii_letters + string.digits, k=length - 1))
    return first + rest


# Class / method names to replace (longest first)
CLASS_NAMES = [
    'RunExMainClass',
    'RunExException',
    'WindowStationDACL',
    'NativeMethods',
    'AccessToken',
    'RunExMain',
    'MainClass',
    'RunEx',
]

# Strings to strip entirely
BRANDING = [
    'RunEx v2.0',
    '@totekuh',
]


def collect_auto_identifiers(all_source):
    """Extract delegate types, cached fields, method names, and field
    names that are worth renaming."""
    idents = set()

    # Delegate types: "private delegate ... SomeName_t("
    for m in re.finditer(r'private delegate \S+ (\w+_t)\(', all_source):
        idents.add(m.group(1))

    # Cached fields: "private static SomeType_t _SomeName;"
    for m in re.finditer(r'private static \w+_t (_\w+);', all_source):
        idents.add(m.group(1))

    # Methods with any access modifier (internal/private/public, static or not)
    for m in re.finditer(r'(?:internal|private|public)\s+(?:static\s+)?\S+\s+(\w+)\(', all_source):
        idents.add(m.group(1))

    # Private/internal fields
    for m in re.finditer(r'private\s+(?:static\s+)?(?:readonly\s+)?\w+(?:\[\])?\s+(\w+)\s*[;=]', all_source):
        idents.add(m.group(1))

    return idents


# Names that must not be renamed (entry points, framework overrides, etc.)
SKIP = {
    'Main', 'ToString', 'GetHashCode', 'Equals', 'Dispose',
    'GetModuleHandle', 'LoadLibrary', 'GetProcAddress',  # bootstrap P/Invokes
}


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <src_dir> <build_dir>", file=sys.stderr)
        sys.exit(1)

    src_dir, build_dir = sys.argv[1], sys.argv[2]
    os.makedirs(build_dir, exist_ok=True)

    # Read all source files
    files = {}
    for fname in sorted(os.listdir(src_dir)):
        if not fname.endswith('.cs'):
            continue
        with open(os.path.join(src_dir, fname)) as f:
            files[fname] = f.read()

    all_source = '\n'.join(files.values())

    # Build the full replacement mapping
    mapping = []

    # Auto-detected identifiers (delegates, fields, methods)
    for name in collect_auto_identifiers(all_source):
        if len(name) < MIN_IDENT_LEN or name in SKIP:
            continue
        mapping.append((name, rand_id()))

    # Class names
    for name in CLASS_NAMES:
        if name not in SKIP:
            mapping.append((name, rand_id()))

    # Deduplicate (same name may appear in both auto and CLASS_NAMES)
    seen = set()
    deduped = []
    for old, new in mapping:
        if old not in seen:
            seen.add(old)
            deduped.append((old, new))
    mapping = deduped

    # Sort longest-first to prevent partial replacements
    mapping.sort(key=lambda x: len(x[0]), reverse=True)

    # Compile word-boundary regex for each identifier
    compiled = [(re.compile(r'\b' + re.escape(old) + r'\b'), new) for old, new in mapping]

    # Apply
    n_files = 0
    for fname, content in files.items():
        # Strip branding first (before identifiers mangle the strings)
        for brand in BRANDING:
            content = content.replace(brand, '')
        for pattern, new in compiled:
            content = pattern.sub(new, content)
        with open(os.path.join(build_dir, fname), 'w') as f:
            f.write(content)
        n_files += 1

    print(f"Obfuscated {len(mapping)} identifiers across {n_files} files", file=sys.stderr)


if __name__ == '__main__':
    main()
