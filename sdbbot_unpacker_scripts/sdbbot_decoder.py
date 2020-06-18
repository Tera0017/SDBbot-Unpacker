"""
Author:@Tera0017
Extracts Installer module
"""
import pefile
import struct
from sdbbot_gen_funcs import rol, to_hex_dword, to_str_dword, readFile, match_rule, message, fix_dword, hexy


class SDBbotDecoder:

    def __init__(self, filepath, osa, rules):
        self.filepath = filepath
        self.pe = pefile.PE(name=self.filepath, fast_load=True)
        self.filedata = readFile(self.filepath)
        self.osa = osa
        self.rules = rules

    def encoded_data(self, address, size):
        size *= 4
        encoded_data = self.pe.get_data(address, size)
        return [to_hex_dword(encoded_data[i:i + 4]) for i in range(0, len(encoded_data), 4)]

    def xor_rol_value(self):
        ind = 2 if self.osa == 0x32 else 1
        for rl in ['$code1']:
            for match in match_rule(rl, self.rules[rl], self.filedata):
                opcodes = match.strings[0][2]
                xor_val = to_hex_dword(opcodes[ind: ind + 4])
                rol_val = int(opcodes[-2: -1].encode('hex'), 16)
                return xor_val, rol_val
        return None, None

    def encoded_code_address(self):
        ind = 3 if self.osa == 0x32 else 4
        for rl in ['$code2']:
            for match in match_rule(rl, self.rules[rl], self.filedata):
                opcodes = match.strings[0][2]
                ind = ind + 3 if 'C78424'.decode('hex') == opcodes[:3] else ind
                value = to_str_dword(to_hex_dword(opcodes[ind: ind + 4]) - 1)
                address = self.pe.get_rva_from_offset(match.strings[0][0])
                data_search = self.pe.get_data(address, 150)
                size = self.encoded_size(data_search)
                address = self.pe.get_rva_from_offset(self.filedata.index(value) + 4)
                return address, size
        return None, None

    def encoded_size(self, data):
        for rl in ['$code3']:
            for match in match_rule(rl, self.rules[rl], data):
                opcodes = match.strings[0][2]
                return to_hex_dword(opcodes[-1 - 4: -1])
        return None

    def decode_code(self):
        enc_addr, size_loop = self.encoded_code_address()
        xor_val, rol_val = self.xor_rol_value()

        message('Encoded code ROL {}'.format(int(rol_val)))
        message('Encoded code XOR Key: {}'.format(hex(xor_val).upper()))
        message('Encoded code Size: {}'.format(hex(size_loop).upper()))
        encoded_data = self.encoded_data(enc_addr, size_loop)
        decoded_code = ''
        for i in range(0, size_loop):
            dword = encoded_data[i]
            dword ^= xor_val
            dword = rol(dword, rol_val)
            if self.osa == 0x64:
                dword ^= xor_val
            decoded_code += to_str_dword(dword)
        return decoded_code

    def rol_value(self, code):
        for rule in ['$code4']:
            for match in match_rule(rule, self.rules[rule], code):
                return int(match.strings[0][2][-1].encode('hex'), 16)
        return None

    def xor_size_value(self):
        address = None
        for rl in ['$code1']:
            for match in match_rule(rl, self.rules[rl], self.filedata):
                address = self.pe.get_rva_from_offset(match.strings[0][0])
                break
        if address is not None:
            data = self.pe.get_data(address, 900)
            for rl in ['$code5']:
                for match in match_rule(rl, self.rules[rl], data):
                    opcodes = match.strings[0][2]
                    if self.osa == 0x32:
                        opcodes = ['\xC7\x45' + op for op in opcodes.split('\xC7\x45') if op.strip()]
                    else:
                        opcodes = opcodes.replace('\xC7\x44\x24', '\xC7\x84\x24')
                        opcodes = ['\xC7\x84\x24' + op for op in opcodes.split('\xC7\x84\x24') if op.strip()]
                    size = to_hex_dword(opcodes[0][-4:])
                    xor = to_hex_dword(opcodes[1][-4:])
                    return xor, size
        return None, None

    def get_last_import(self):
        self.pe.parse_data_directories()
        entry = self.pe.DIRECTORY_ENTRY_IMPORT[-1]
        imp = entry.imports[-1]
        return imp.address

    def enc_mz_address(self):
        ind = 4 if self.osa == 0x32 else 8
        addr = self.get_last_import()
        addr += (2 * ind) - self.pe.OPTIONAL_HEADER.ImageBase
        data = self.pe.get_data(addr, 20)
        if data.startswith('\x00\x00\x00\x00'):
            addr += ind
        return addr

    @staticmethod
    def pickup_exact_code(temp_code):
        enc_exec_code = ''
        ps_add = 1
        mod_val = 2
        pos_counter = 0
        counter = 0
        while pos_counter < len(temp_code) - 1:
            if not counter % mod_val:
                pos_counter += ps_add
            enc_exec_code += temp_code[pos_counter]
            pos_counter += 1
            counter += 1
        return fix_dword(enc_exec_code)

    def decode_layer(self, temp_code, xor_key, rol_val):
        temp_code = [struct.unpack('I', temp_code[i:i + 4])[0] for i in range(0, len(temp_code), 4)]
        compressed = ''
        for i in range(0, len(temp_code)):
            dword_enc = temp_code[i]
            dword_enc ^= xor_key
            dword_enc = (rol(dword_enc, rol_val)) & 0xFFFFFFFF
            dword_enc ^= ((xor_key >> 0x10) & 0xFFFF) if self.osa == 0x32 else xor_key
            compressed += struct.pack("I", dword_enc)
        return compressed

    def decode_mz(self, code):
        rol_val = self.rol_value(code)
        xor_key, size = self.xor_size_value()
        message('Encoded Binary ROL {}'.format(rol_val))
        message('Encoded Binary XOR Key: {}'.format(hex(xor_key).upper()))
        message('Encoded Binary Size: {}'.format(hex(size).upper()))
        enc_mz_addr = self.enc_mz_address() + 4
        if self.osa == 0x32:
            enc_mz_data = self.pickup_exact_code(self.pe.get_data(enc_mz_addr, size * 4))
        else:
            enc_mz_data = self.pe.get_data(enc_mz_addr, size * 4)
        comp_mz_data = self.decode_layer(enc_mz_data, xor_key, rol_val)
        decompress = Decompress(comp_mz_data)
        decompress.decompress()
        return decompress.get_decompressed()

    def decode(self):
        decoded_code = self.decode_code()
        open('/home/tera/FL.bin', 'wb').write(decoded_code)
        decoded_exec = self.decode_mz(decoded_code)
        return decoded_exec


class SDBbotDecoderx86(SDBbotDecoder):

    def __init__(self, filepath):
        rules = {
            '$code1': '{(81 (F1| F2)| FF 35) ?? ?? ?? ?? [5-20] C1 C? (03| 07) 89}',
            '$code2': '{C7 45 ?? ?? ?? ?? ?? 8B ?? ?? (48| 83 (E8| EA| E9) 01) 89}',
            '$code3': '{81 ?D [3-6] 00 00 (73| 75| 0F)}',
            '$code4': '{C1 C0 0?}',
            '$code5': '{C7 45 [5] C7 45 [5] C7 45 [5] (8B| 89)}'
        }
        SDBbotDecoder.__init__(self, filepath, 0x32, rules)


class SDBbotDecoderx64(SDBbotDecoder):

    def __init__(self, filepath):
        rules = {
            '$code1': '{35 ?? ?? ?? ?? 89 (44 24 ??| 84 24 [2] 00 00) 8B (44 24 ??| 84 24 [2] 00 00) C1 C? 0? 89}',
            '$code2': '{C7 (44 24 ??| 84 24 [2] 00 00) ?? ?? ?? ?? 8B (44 24 ??| 84 24 [2] 00 00) (FF C8| 83 (E8| EA| E9) 01)}',
            '$code3': '{48 3D [2] 00 00 (73| 75| 0F)}',
            '$code4': '{C1 C0 0?}',
            '$code5': '{C7 (44 24 ??| 84 24 [2] 00 00) ?? ?? ?? ?? C7 (44 24 ??| 84 24 [2] 00 00) ?? ?? ?? ?? C7 (44 24 ??| 84 24 [2] 00 00) ?? ?? ?? ?? 48}',
        }
        SDBbotDecoder.__init__(self, filepath, 0x64, rules)


class Decompress:
    def __init__(self, compressed):
        self.compressed = compressed
        self.decrypted_exec = []
        self.config = {'mem_in_counter': 1, 'mem_out_counter': 1,
                       'value': '', 'rev_counter': 0,
                       'stop_flag': 0,
                       'var_14': 0, 'var_10': 0, 'var_8_loop': 4, 'var_C': -1, 'var_4': 0, 'loop_var_4': 1}

    def conf_val_rev(self):
        self.config['rev_counter'] -= 1
        if self.config['rev_counter'] == -1:
            self.config['value'] = ord(self.compressed[self.config['mem_in_counter']])
            self.config['mem_in_counter'] += 1
            self.config['rev_counter'] = 7
        ret_val = (self.config['value'] >> 7) & 1
        self.config['value'] = (self.config['value'] << 1) & 0xFFFFFFFF
        return ret_val

    def loop_conf_val_rev(self):
        self.config['loop_var_4'] = 1
        while True:
            temp1 = self.conf_val_rev()
            self.config['loop_var_4'] = temp1 + self.config['loop_var_4'] * 2
            if not self.conf_val_rev():
                break
        return self.config['loop_var_4']

    def get_decompressed(self):
        return ''.join(self.decrypted_exec)

    def decompress(self):
        self.decrypted_exec = list(self.compressed[0])
        while self.config['stop_flag'] == 0:
            if self.conf_val_rev():
                if self.conf_val_rev():
                    if self.conf_val_rev():
                        self.config['var_14'] = 0
                        for self.config['var_8_loop'] in range(4, 0, -1):
                            ret_val = self.conf_val_rev()
                            self.config['var_14'] = ret_val + (self.config['var_14'] * 2) & 0xFFFFFFFF
                        self.config['var_8_loop'] = 0
                        if self.config['var_14'] == 0:
                            # loc_A20
                            self.config['mem_out_counter'] += 1
                            self.decrypted_exec += ['\x00']
                        else:
                            self.decrypted_exec += [self.decrypted_exec[self.config['mem_out_counter'] - self.config['var_14']]]
                            self.config['mem_out_counter'] += 1
                        self.config['var_4'] = 0
                    else:
                        # loc_A8B
                        self.config['var_14'] = ord(self.compressed[self.config['mem_in_counter']])
                        self.config['mem_in_counter'] += 1
                        self.config['var_10'] = (self.config['var_14'] & 1) + 2
                        self.config['var_14'] >>= 1
                        if self.config['var_14']:
                            # loc_A6B
                            while self.config['var_10']:
                                self.decrypted_exec += [self.decrypted_exec[self.config['mem_out_counter'] - self.config['var_14']]]
                                self.config['mem_out_counter'] += 1
                                self.config['var_10'] -= 1
                            self.config['var_C'] = self.config['var_14']
                        else:
                            # loc_A8B
                            self.config['stop_flag'] = 1

                        self.config['var_C'] = self.config['var_14']
                        self.config['var_4'] = 1
                else:
                    self.config['var_14'] = self.loop_conf_val_rev()
                    if self.config['var_4'] or self.config['var_14'] != 2:
                        if self.config['var_4'] != 0:
                            self.config['var_14'] -= 2
                        else:
                            self.config['var_14'] -= 3
                        # loc_B1C
                        self.config['var_14'] = (self.config['var_14'] << 8) & 0xFFFFFFFF
                        self.config['var_14'] += ord(self.compressed[self.config['mem_in_counter']])
                        self.config['mem_in_counter'] += 1

                        self.config['var_10'] = self.loop_conf_val_rev()
                        if self.config['var_14'] >= 0x7D00:
                            self.config['var_10'] += 1

                        if self.config['var_14'] >= 0x500:
                            self.config['var_10'] += 1

                        if self.config['var_14'] < 0x80:
                            self.config['var_10'] += 2

                        while self.config['var_10']:
                            self.decrypted_exec += [self.decrypted_exec[self.config['mem_out_counter'] - self.config['var_14']]]
                            self.config['mem_out_counter'] += 1
                            self.config['var_10'] -= 1
                        self.config['var_C'] = self.config['var_14']
                    else:
                        self.config['var_14'] = self.config['var_C']
                        ret_val = self.loop_conf_val_rev()
                        self.config['var_10'] = ret_val
                        while self.config['var_10']:
                            # loc_ADF
                            self.decrypted_exec += [self.decrypted_exec[self.config['mem_out_counter'] - self.config['var_14']]]
                            self.config['mem_out_counter'] += 1
                            self.config['var_10'] -= 1
                    self.config['var_4'] = 1
            else:
                self.decrypted_exec += [self.compressed[self.config['mem_in_counter']]]
                self.config['mem_out_counter'] += 1
                self.config['mem_in_counter'] += 1
                self.config['var_4'] = 0
