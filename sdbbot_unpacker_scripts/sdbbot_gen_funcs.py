# -*- coding: utf-8 -*-
"""
Author:@Tera0017
"""
import yara
import pefile
import struct
import argparse
ERROR01 = 'Make sure this sample is a packed SDBbot else DM hash @Tera0017'


tmp_rule = '''
rule match_rule
{
    strings:
        %s = %s
    condition:
        any of them
}'''.strip()


def readFile(name):
    return open(name, 'rb').read()


def writeFile(name, data):
    open(name, 'wb').write(data)


def process_args():
    logo()
    message('SDBbot Unpacker')
    parser = argparse.ArgumentParser(description='SDBbot Modules Unpacker')
    parser.add_argument('-f', '--file', type=str, help='File to unpack modules.')
    return parser.parse_args()


def get_osa(file_data=None, file_path=None):
    if file_data is not None:
        pe = pefile.PE(data=file_data, fast_load=True)
    else:
        pe = pefile.PE(name=file_path, fast_load=True)
    # 0x014C == x86, 0x8664 == x86-x64
    return 0x32 if pe.FILE_HEADER.Machine == 0x14c else 0x64


def to_hex_dword(val):
    return struct.unpack('<I', val)[0]


def to_str_dword(val):
    try:
        return struct.pack('<I', val)
    except struct.error:
        return struct.pack('<Q', val)


def split_per(line, n):
    return [line[i:i + n] for i in range(0, len(line), n)]


def rol(dword, n):
    n = n % 32
    return (dword << n | dword >> (32 - n)) & 0xFFFFFFFF


def is_ascii(s):
    return all(ord(c) < 128 for c in s)


def match_rule(rule_name, rule_val, data):
    myrules = tmp_rule % (rule_name, rule_val)
    yararules = yara.compile(source=myrules)
    return yararules.match(data=data)


def hexy(st):
    line = " ".join("{:02x}".format(ord(c)) for c in st).upper()
    n = 96
    return '\n'.join([line[i:i + n] for i in range(0, len(line), n)])


def get_section_data(name, filepath):
    pe = pefile.PE(name=filepath, fast_load=True)
    for section in pe.sections:
        if section.Name.startswith(name):
            address = section.VirtualAddress
            size = section.SizeOfRawData
            data = pe.get_data(address, size)
            return data
    return None


def get_section_address(name, filepath):
    pe = pefile.PE(filepath, fast_load=True)
    for section in pe.sections:
        if section.Name.startswith(name):
            return section.VirtualAddress


def get_exports(pe):
    export_dir = [i for i in pe.OPTIONAL_HEADER.DATA_DIRECTORY if 'export' in i.name.lower()][0]
    exports_no = to_hex_dword(pe.get_data(export_dir.VirtualAddress + 20, 4))
    data = pe.get_data(export_dir.VirtualAddress + 40, exports_no * 4)
    exp = {}
    for i in range(0, len(data), 4):
        exp[i / 4] = struct.unpack('I', data[i: i + 4])[0]
    return exp


def fix_dword(enc_data):
    for i in range(0, 4 - len(enc_data) % 4):
        enc_data += '\x00'
    return enc_data


def message(msg):
    print '|--> {}'.format(msg)


def gen_name(file_path, new_name):
    import os
    filename = os.path.basename(file_path)
    folder = file_path.replace(filename, '')
    return folder + new_name + filename


def get_size(file_data):
    pe = pefile.PE(data=file_data)
    total_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    for section in pe.sections:
        total_size += section.SizeOfRawData
    return total_size


def edit_data(data, index, change):
    start = data[:index]
    end = data[index + len(change):]
    z = start + change + end
    return z


def extract_binaries(data):
    extract = True
    st = data[2:].index('MZ') + 2
    while extract:
        try:
            mz_data = data[st:]
            total_size = get_size(mz_data)
            start = st
            end = start + total_size
            mz_data = data[start:end]
            return mz_data
        except pefile.PEFormatError:
            try:
                st = st + data[st + 2:].index('MZ') + 2
            except ValueError:
                break
        except ValueError:
            break
    return None


def logo():
    print u'''
  ____  ____  ____  _           _     _   _                  _         
 / ___||  _ \| __ )| |__   ___ | |_  | | | |_ __  _ __   ___| | ___ __ 
 \___ \| | | |  _ \| '_ \ / _ \| __| | | | | '_ \| '_ \ / __| |/ / '__|
  ___) | |_| | |_) | |_) | (_) | |_  | |_| | | | | |_) | (__|   <| |   
 |____/|____/|____/|_.__/ \___/ \__|  \___/|_| |_| .__/ \___|_|\_\_|   
                                                 |_|'''
