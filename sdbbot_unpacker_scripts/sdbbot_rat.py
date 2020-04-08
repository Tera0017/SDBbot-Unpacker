"""
Author:@Tera0017
Extracts RAT module
"""
import lznt1
from sdbbot_gen_funcs import get_section_data, fix_dword


class SDBbotRat:

    def __init__(self, filepath, osa):
        self.filepath = filepath
        self.osa = osa

    def rat_module(self):
        import struct
        rat_data = get_section_data('.data1', self.filepath)
        rat_data = fix_dword(rat_data[rat_data.index('MZ') - 3:].rstrip('\x00'))
        try:
            return lznt1.decompress(rat_data, length_check=False)
        except struct.error:
            return lznt1.decompress(rat_data + '\x00', length_check=False)

    def decode(self):
        data = self.rat_module()
        return data


class SDBbotRatx86(SDBbotRat):

    def __init__(self, filepath):
        SDBbotRat.__init__(self, filepath, 0x32)


class SDBbotRatx64(SDBbotRat):

    def __init__(self, filepath):
        SDBbotRat.__init__(self, filepath, 0x64)
