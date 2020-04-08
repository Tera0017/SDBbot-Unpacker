"""
Author:@Tera0017
Extracts Loader module (loader code is stored in Registry Blob as well)
Some random values are hardcoded.
"""
import pefile
from sdbbot_gen_funcs import readFile, extract_binaries, get_exports, to_str_dword, edit_data


class SDBbotLoader:

    def __init__(self, filepath, osa):
        self.filepath = filepath
        self.osa = osa

    def decode(self):
        loader_code = extract_binaries(readFile(self.filepath))
        # now the malware is patching some export values (some "random")
        pe = pefile.PE(data=loader_code)
        exports = get_exports(pe)
        exports_write = {
            2: '\x00'.join(list("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\ter")),
            3: 't',
            5: '-SDBbot-Random-XORKey-@Tera0017-' * 4,
            6: to_str_dword(pe.OPTIONAL_HEADER.ImageBase),
        }
        for exp in exports:
            if exp + 1 not in exports_write:
                continue
            address = pe.get_offset_from_rva(exports[exp])
            data = exports_write[exp + 1]
            loader_code = edit_data(loader_code, address, data)
        # #1 and some other functions are encrypted with the XOR key (I ignore this step)
        # #2 reg path and 3 random chars
        # #3 1 random char
        # #5 contains the xor key of len 0x80, I will add some "random" value
        # #6 image base
        return loader_code


class SDBbotLoaderx86(SDBbotLoader):

    def __init__(self, filepath):
        SDBbotLoader.__init__(self, filepath, 0x32)


class SDBbotLoaderx64(SDBbotLoader):

    def __init__(self, filepath):
        SDBbotLoader.__init__(self, filepath, 0x64)
