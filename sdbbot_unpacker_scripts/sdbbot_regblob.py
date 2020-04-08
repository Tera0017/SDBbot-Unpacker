"""
Author:@Tera0017
Extracts RegistryBlob contains Loader code to load RAT module, and RAT module
Some random values are hardcoded.
"""
import pefile
from sdbbot_gen_funcs import get_section_data, readFile, match_rule, to_hex_dword

BLOB_STRUCTURE = '{copyright}{loader_code}{random_chars}{rat_module}'


class SDBbotRegBlob:

    def __init__(self, filepath, osa, rules):
        self.filepath = filepath
        self.filedata = readFile(self.filepath)
        self.pe = pefile.PE(self.filepath, fast_load=True)
        self.osa = osa
        self.rules = rules

    def decode(self):
        copyright = 'Copyright (C) Microsoft Corporation.'
        loader_shellcode = self.decode_loader_shellcode()
        # 3 random characters
        random_chrs = 'ter' + '0INIT'
        rat = get_section_data('.data1', self.filepath)
        return BLOB_STRUCTURE.format(
            copyright=copyright,
            loader_code=loader_shellcode,
            random_chars=random_chrs,
            rat_module=rat
        )

    def decode_loader_shellcode(self):
        shell = [ord(i) for i in list(self.loader_shellcode())]
        xor = [ord(i) for i in list(self.xor_key())]
        for i in range(0, len(shell)):
            shell[i] ^= xor[i & 0x7F]
        shell = ''.join([chr(i) for i in shell])
        return shell

    def loader_shellcode(self):
        ind1, ind2 = {0x32: (14, 22), 0x64: (27, 34)}[self.osa]
        encoded_shellcode = ''
        for rl in ['$code1']:
            for match in match_rule(rl, self.rules[rl], self.filedata):
                opcodes = match.strings[0][2]
                size = to_hex_dword(opcodes[ind1: ind1 + 4])
                address = to_hex_dword(opcodes[ind2:ind2 + 4])
                if self.osa == 0x32:
                    address = address - self.pe.OPTIONAL_HEADER.ImageBase
                else:
                    rule_addr = match.strings[0][0] + 38
                    address = self.pe.get_rva_from_offset(address + rule_addr - self.pe.OPTIONAL_HEADER.SizeOfHeaders)
                encoded_shellcode = self.pe.get_data(address, size)
            return encoded_shellcode

    def xor_key(self):
        ind = {0x32: 7, 0x64: 3}[self.osa]
        for rl in ['$code2']:
            for match in match_rule(rl, self.rules[rl], self.filedata):
                address = to_hex_dword(match.strings[0][2][ind: ind + 4])
                if self.osa == 0x32:
                    address -= self.pe.OPTIONAL_HEADER.ImageBase
                else:
                    rule_addr = match.strings[0][0] + 7
                    address = self.pe.get_rva_from_offset(address + rule_addr - self.pe.OPTIONAL_HEADER.SizeOfHeaders)
                return self.pe.get_data(address, 128)


class SDBbotRegBlobx86(SDBbotRegBlob):

    def __init__(self, filepath):
        rule = {
            '$code1': '{6A 24 68 [4] 56 E8 [4] 68 ?? ?? 00 00 [3] 68 ?? ?? ?? ?? 50 E8 [4] 6A 08}',
            '$code2': '{8B C8 83 E1 7F 8A 89 ?? ?? ?? ?? 30 0C 30 40 3B C2}',
        }
        SDBbotRegBlob.__init__(self, filepath, 0x32, rule)


class SDBbotRegBlobx64(SDBbotRegBlob):

    def __init__(self, filepath):
        rule = {
            '$code1': '{41 ?? 24 00 00 00 48 [6] 49 [2] E8 [4] 49 [3] 41 [3] 00 00 48 [6] E8 [4] 49 [6] 41 ?? 08 00 00 00}',
            '$code2': '{4C 8D 0D ?? ?? ?? ?? 49 8B C0 48 8D 49 01 83 E0 7F}',
        }
        SDBbotRegBlob.__init__(self, filepath, 0x64, rule)
