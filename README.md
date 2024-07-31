# Persephone
A simple PoC for automating shellcode patching with Python! Engineered to work hand in hand with 0xTriboulet's Hades Scanner.

![image](https://github.com/user-attachments/assets/d4958573-3ea4-4972-b5b1-f19bc2fdc786)

### Lore ###
Persephone is a mythological Goddess who is the daughter of Zeus in Greek Mythology. Eventually, she became Hades' partner and Queen of the underworld. Thus, as is the relationship between Hades and Persephone closely intertwined, so is the usage of Persephone.py alongside the Hades Scanner to perform shellcode patching!

### Installation ###
cd /path/to/install_dir
git clone --recursive https://https://github.com/Steveo21/Persephone

### Usage ###
First, scan a shellcode (.bin) file with the Hades Scanner https://www.patreon.com/posts/hades-scanner-v0-95235247?l=de :
Hades.py --ruleset_path /path/to/rulelist.yar /path/to/shellcode.bin > flagged_strings_file

Then, use Persephone to patch the shellcode based on the generated flagged_strings_file by Hades!

Persephone.py /path/to/flagged_strings_file /path/to/shellcode.bin

In it's current stage of development, Persephone output's a .bin file "zagreus.bin" (Child of Hades and Persephone) in the relative directory where it was run, preserving the unpatched copy of shellcode.bin to streamline testing

### Intent ###
Persephone was designed for two primary reasons, learning more about automation with python from an offensive perspective and acting as a repository of "rules" to help me learn assembly. That being said, Persephone only currently has one "rule" that it patches for: xor operations of 64-bit general purpose registers against themselves. Effectively, this removes the byte "48" from the sequence and appends a NOP, maintaining proper size and alignment to ensure no issues with functionality arise. The more shellcode I patch and the techniques I discover to do so I will update the script and this repository to reflect. If nothing else, Persephone serves as a foundational PoC of shellcode patching. 

### PoC Testing ###
//NOTE that testing was done against 64 bit metasploit calc shellcode with Florian Roth's Yara Forge (Full) Ruleset https://yarahq.github.io/: 
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin






