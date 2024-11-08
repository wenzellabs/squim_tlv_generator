class MetaInterface(type):
    def __getattr__(cls, key):
        return cls[key]
    def __setattr__(cls, key, val):
        raise TypeError

class Interface(object, metaclass=MetaInterface):
    def __getattr__(self, name):
        return self[name]
    def __setattr__(self, name, val):
        raise TypeError

class Config(Interface):
    udp_port = 11000
    indent_py = "    "
    indent_c = "    "
    input = "input"
    generated_python = "../squim_player/generated_tlv.py"
    generated_include = "../pico-square-immersion/src/generated_tlv.h"
