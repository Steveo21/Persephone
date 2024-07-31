import sys
import re

def parse_hades_output(hades_output_file):
    rules = []
    with open(hades_output_file, 'r') as file:
        current_rule = {}
        for line in file:
            if line.startswith('Rule:'):
                if current_rule:
                    rules.append(current_rule)
                current_rule = {'rule': line.strip(), 'data': '', 'offsets': []}
            elif 'Data:' in line:
                current_rule['data'] = line.split(':')[1].strip()
            elif 'Offset:' in line:
                offset = int(line.split(':')[1].strip(), 16)
                current_rule['offsets'].append(offset)
        if current_rule:
            rules.append(current_rule)
    return rules

def read_shellcode(shellcode_file):
    with open(shellcode_file, 'rb') as file:
        return bytearray(file.read())

def patch_shellcode(shellcode, offset, pattern, replacement):
    pattern_bytes = bytes.fromhex(pattern)
    replacement_bytes = bytes.fromhex(replacement)
    end_idx = offset + len(pattern_bytes)
    if shellcode[offset:end_idx] == pattern_bytes:
        shellcode[offset:end_idx] = replacement_bytes
        return True
    return False

def main():
    if len(sys.argv) != 3:
        print("Usage: Persephone <hades_output_file> <shellcode.bin>")
        sys.exit(1)

    hades_output_file = sys.argv[1]
    shellcode_file = sys.argv[2]

    rules = parse_hades_output(hades_output_file)
    shellcode = read_shellcode(shellcode_file)

    xor_patterns = {
        '4831d2': '31d290',
        '4831c0': '31c090',
        '4831c9': '31c990',
        '4831db': '31db90',
        '4831e4': '31e490',
        '4831ed': '31ed90',
        '4831f6': '31f690',
        '4831ff': '31ff90',
    }

    for rule in rules:
        print(f"\n{rule['rule']}")
        data = rule['data']
        for offset in rule['offsets']:
            for pattern, replacement in xor_patterns.items():
                pattern_bytes = bytes.fromhex(pattern)
                if pattern_bytes in bytes.fromhex(data):
                    print(f"[+] xor operation detected at offset {offset:08x}, would you like to patch this operation? y/n")
                    response = input().strip().lower()
                    if response == 'y':
                        if patch_shellcode(shellcode, offset, pattern, replacement):
                            print(f"Patched {pattern} to {replacement} at offset {offset:08x}")
                        else:
                            print(f"Failed to patch {pattern} at offset {offset:08x}")

    with open('zagreus.bin', 'wb') as file:
        file.write(shellcode)
    print("Patched shellcode saved as zagreus.bin")

if __name__ == "__main__":
    main()
