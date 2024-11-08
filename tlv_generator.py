#!/usr/bin/env python3

from config import Config
from enum import Enum
import re

class State(Enum):
    INIT = 1
    NODE = 2
    TYPE = 3
    ITEM = 4

class TLV_Node():
    def __init__(self, name, node_nonce, str_pack_unpack, param_list, datatype, extra_args):
        self.name = name
        self.node_nonce = node_nonce
        self.str_pack_unpack = str_pack_unpack
        self.param_list = param_list
        self.datatype = datatype
        self.extra_args = extra_args

class TLV_generator:

    def __init__(self, config):
        self.config = config
        self.fh_py_out = open(self.config.generated_python, 'w')
        self.fh_c_out = open(self.config.generated_include, 'w')
        self.node_list = []

        self.tag_pack_unpack_map ={
            'u8': 'B',
            'i8': 'b',
            'u16': 'H',
            'i16': 'h',
            'u32': 'I',
            'i32': 'i',
            'u64': 'Q',
            'i64': 'q',
            'enum': 'B'
        }
        self.tag_c_map ={
            'u8': 'uint8_t',
            'i8': 'int8_t',
            'u16': 'uint16_t',
            'i16': 'int16_t',
            'u32': 'uint32_t',
            'i32': 'int32_t',
            'u64': 'uint64_t',
            'i64': 'int64_t',
            'enum': 'replaced by tlv_enum_XXX_t'
        }

    def emit_py_header(self):
        self.print_py('# this stuff is automagically generated from\n')
        self.print_py('# tlv_generator.py - do not edit\n')
        self.print_py('\n')
        self.print_py('import struct\n')
        self.print_py('from enum import Enum\n')
        self.print_py('\n')
        self.print_py('\n')
        self.print_py_indented(0, '# base TLV Packet class\n')
        self.print_py_indented(0, 'class TLVPacket:\n')
        self.print_py_indented(1, 'def __init__(self, type, payload):\n')
        self.print_py_indented(2, 'self.type = type\n')
        self.print_py_indented(2, 'self.len = 2 + len(payload)  # header length is 2 bytes\n')
        self.print_py_indented(2, 'self.payload = payload\n')
        self.print_py('\n')
        self.print_py_indented(1, 'def to_bytes(self):\n')
        self.print_py_indented(2, 'header = struct.pack(\'<BB\', self.type, self.len)\n')
        self.print_py_indented(2, 'return header + self.payload\n')
        self.print_py('\n')
        self.print_py_indented(1, '@staticmethod\n')
        self.print_py_indented(1, 'def from_bytes(data):\n')
        self.print_py_indented(2, 'type, length = struct.unpack(\'<BB\', data[:2])\n')
        self.print_py_indented(2, 'payload = data[2:length]\n')
        self.print_py_indented(2, 'return TLVPacket(type, payload)\n')
        self.print_py('\n')
        self.print_py('\n')
        self.print_py('# derived classes for specific TLV types\n')
        self.print_py('\n')

    def emit_py_nodes(self):
        for n in self.node_list:
            self.print_py_indented(0, f'class TLVPacket{self.capitalize(n.name)}(TLVPacket):\n')

            # enums
            enums = [e for e, x in enumerate(n.datatype) if x == 'enum']
            for e in enums:
                self.print_py_indented(1, f'Enum_{n.param_list[e]} = Enum(\'Enum_{n.param_list[e]}\', {n.extra_args[e]})\n')

            self.print_py_indented(1, f'def __init__(self')
            for i in range(len(n.param_list)):
                if n.datatype[i] == 'array':
                    self.print_py(f', {n.extra_args[i][0]}')
                else:
                    self.print_py(f', {n.param_list[i]}')
            self.print_py_indented(0, f'):\n')

            self.print_py_indented(2, f'tlv_nonce = {n.node_nonce}\n')

            if len(n.param_list) > 0:
                self.print_py_indented(2, f'payload = struct.pack(\'<{n.str_pack_unpack}\'')
                for i in range(len(n.param_list)):
                    if n.datatype[i] == 'enum':
                        self.print_py(f', {n.param_list[i]}.value')
                    elif n.datatype[i] == 'array':
                        self.print_py(f', *{n.extra_args[i][0]}')
                    else:
                        self.print_py(f', {n.param_list[i]}')
                self.print_py_indented(0, f')\n')
            else:
                self.print_py_indented(2, f'payload = b\'\'\n')

            self.print_py_indented(2, f'super().__init__(tlv_nonce, payload)\n')
            self.print_py_indented(0, f'\n')
            self.print_py_indented(1, f'@staticmethod\n')
            self.print_py_indented(1, f'def from_bytes(data):\n')
            if len(n.param_list) > 0:
                self.print_py_indented(2, f'')
                for i in range(len(n.param_list)):
                    if n.datatype[i] == 'array':
                        self.print_py(f'*{n.extra_args[i][0]}, ')
                    else:
                        self.print_py(f'{n.param_list[i]}, ')
                self.print_py_indented(0, f'= struct.unpack(\'<{n.str_pack_unpack}\', data[2:])\n')
            self.print_py_indented(2, f'return TLVPacket{self.capitalize(n.name)}(')
            for i in range(len(n.param_list)):
                if n.datatype[i] == 'array':
                    self.print_py(f'{n.extra_args[i][0]}, ')
                else:
                    self.print_py(f'{n.param_list[i]}, ')
            self.print_py_indented(0, f')\n')
            self.print_py_indented(0, f'\n')

    def emit_py_footer(self):
        self.print_py('\n')
        self.print_py('# end of automagically generated code\n')

    def emit_c_header(self):
        self.print_c('/* this stuff is automagically generated from */\n')
        self.print_c('/* tlv_generator.py - do not edit */\n')
        self.print_c('\n')
        self.print_c('#pragma once\n')
        self.print_c('\n')
        self.print_c('#ifdef __cplusplus\n')
        self.print_c('extern "C"\n')
        self.print_c('{\n')
        self.print_c('#endif\n')
        self.print_c('\n')
        self.print_c('#include <stdint.h>\n')
        self.print_c('\n')
        self.print_c('#define PACKED __attribute__((__packed__))\n')
        self.print_c('\n')
        self.print_c('\n')

    def emit_c_nodes(self):
        for n in self.node_list:
            self.print_c(f'#define TLV_TYPE_{self.camel_to_snake(n.name).upper()} {n.node_nonce}\n')

            # enums
            enums = [e for e, x in enumerate(n.datatype) if x == 'enum']
            for e in enums:
                self.print_c_indented(0, f'typedef enum\n')
                self.print_c_indented(0, f'{{\n')
                count = 1 # to align with the python side where enums start at 1
                for i in n.extra_args[e]:
                    self.print_c_indented(1, f'{self.camel_to_snake(n.param_list[e]).upper()}_{self.camel_to_snake(i).upper()} = {count},\n')
                    count += 1
                self.print_c_indented(0, f'}} tlv_enum_{self.camel_to_snake(n.param_list[e])}_t;\n')

            self.print_c(f'typedef struct tlv_type_{self.camel_to_snake(n.name)}_s\n')
            self.print_c('{\n')
            for p in range(len(n.param_list)):
                if n.datatype[p] == 'enum':
                    self.print_c_indented(1, f'tlv_enum_{self.camel_to_snake(n.param_list[p])}_t {n.param_list[p]};\n')
                elif n.datatype[p] == 'array':
                    self.print_c_indented(1, f'{self.tag_c_map.get(n.param_list[p])} {n.extra_args[p][0]}[{n.extra_args[p][1]}];\n')
                else:
                    self.print_c_indented(1, f'{self.tag_c_map.get(n.datatype[p])} {n.param_list[p]};\n')
            self.print_c(f'}} PACKED tlv_type_{self.camel_to_snake(n.name)}_t;\n')
            self.print_c('\n')

    def emit_c_footer(self):
        self.print_c('\n')
        self.print_c('#ifdef __cplusplus\n')
        self.print_c('}\n')
        self.print_c('#endif\n')
        self.print_c('\n')
        self.print_c('/* end of automagically generated code */\n')

    def capitalize(self, pileOfMoney):
        PileOfMoney = pileOfMoney[0].upper() + pileOfMoney[1:]
        return PileOfMoney

    def camel_to_snake(self, pileOfCamels):
        pile_of_snakes = re.sub(r'([a-z])([A-Z])', r'\1_\2', pileOfCamels).lower()
        return pile_of_snakes

    def print_c(self, string):
        self.fh_c_out.write(string)

    def print_c_indented(self, n_indent, string):
        for i in range(n_indent):
            self.print_c(Config.indent_c)
        self.print_c(string)

    def print_py(self, string):
        self.fh_py_out.write(string)

    def print_py_indented(self, n_indent, string):
        for i in range(n_indent):
            self.print_py(Config.indent_py)
        self.print_py(string)

    def generate(self):
        self.emit_py_header()
        self.emit_py_nodes()
        self.emit_py_footer()
        self.fh_py_out.close()

        self.emit_c_header()
        self.emit_c_nodes()
        self.emit_c_footer()
        self.fh_c_out.close()

    def emit_node(self, name, node_nonce, str_pack_unpack, param_list, datatype, extra_args):
        self.node_list.append(TLV_Node(name, node_nonce, str_pack_unpack, param_list, datatype, extra_args))

    def parse_input(self):
        st = State.INIT
        line_nr = 0
        datatype = []
        param_list = []
        str_pack_unpack = ''
        name = 'bug in tlv generator'
        node_nonce = 'bug in tlv generator'
        extra_args = []
        with open(self.config.input, 'r') as fh:
            for l in fh.readlines():
                line_nr += 1
                if len(l) == 1:
                    continue
                if l[0] == '#':
                    continue
                l = l.split('#', 1)[0].rstrip()  # remove comments and trim trailing whitespace
                # chop newline
                l = l.rstrip()

                # new node
                if l[0] != ' ' and l[0] != '\t':
                    if st != State.INIT:
                        self.emit_node(name, node_nonce, str_pack_unpack, param_list, datatype, extra_args)
                        str_pack_unpack = ''
                        param_list = []
                        datatype = []
                        extra_args = []
                    st = State.NODE
                    name = l
                else:
                    if st == State.NODE:
                        tag = l.split()[0]
                        if tag != 'type':
                            print(f'ERROR: need tag \'type\' after node \'{name}\' definition in line {line_nr} but got \'{tag}\'')
                            exit(1)
                        st = State.ITEM
                        val = l.split()[1]
                        node_nonce = val
                    else:
                        if st == State.ITEM:
                            tag = l.split()[0]
                            val = l.split()[1]

                            param_list.append(val)
                            datatype.append(tag)
                            extra_args.append(l.split()[2:])
                            if tag == 'array':
                                str_pack_unpack += extra_args[-1][1] + self.tag_pack_unpack_map.get(val)
                            else:
                                str_pack_unpack += self.tag_pack_unpack_map.get(tag)

                        else:
                            print(f'bug in tlv generator, input line {line_nr}, last name \'{name}\'')
                            exit(1)
        self.emit_node(name, node_nonce, str_pack_unpack, param_list, datatype, extra_args)

def main():
    tg = TLV_generator(Config)
    tg.parse_input()
    tg.generate()

if __name__ == '__main__':
    main()
