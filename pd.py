##
## MIT License
## Copyright (c) 2024 LabWare
##
## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to deal
## in the Software without restriction, including without limitation the rights
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
##
## The above copyright notice and this permission notice shall be included in all
## copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
## SOFTWARE.
##

import sigrokdecode as srd
from common.srdhelper import bin2int
from capstone import *


# PPC JTAG defines taken from
# https://github.com/ska-sa/roach2_testing/blob/master/roach2_production_test/ocdc_macro_convert.py

#PPC JTAG instruction length
JTAGI_LENGTH = 8
#PPC JTAG data length
JTAGD_LENGTH = 33


class JTAGInstruction:
    pass

class BYPASS(JTAGInstruction):
    def __init__(self, decoder):
        self.decoder = decoder

    def tdi(self, data):
        if len(data) != 64:
            raise Exception('Wrong BYPASS data length')
        self.i = int(data, 2)

    def tdo(self, data):
        if len(data) != 64:
            raise Exception('Wrong BYPASS data length')
        self.o = int(data, 2)
        print("BYPASS IN: 0x%x OUT: 0x%x" % (self.i, self.o))
        self.decoder.put(self.decoder.ss, self.decoder.es, self.decoder.out_ann, [1, ["BYPASS: 0x%x / 0x%x" % (self.i, self.o)]])


class PPCMODE(JTAGInstruction):
    def __init__(self, decoder):
        self.decoder = decoder

    def tdi(self, data):
        if len(data) != JTAGD_LENGTH:
            raise Exception('Wrong PPCMODE data length')
        self.i = int(data, 2)

    def tdo(self, data):
        if len(data) != JTAGD_LENGTH:
            raise Exception('Wrong PPCMODE data length')
        self.o = int(data, 2)
        print("PPCMODE IN: 0x%x OUT: 0x%x" % (self.i, self.o))
        self.decoder.put(self.decoder.ss, self.decoder.es, self.decoder.out_ann, [1, ["PPCMODE: 0x%x / 0x%x" % (self.i, self.o)]])

class PPCINST(JTAGInstruction):
    def __init__(self, decoder):
        self.decoder = decoder

    def tdi(self, data):
        if data=='00000000000000000000000000000000':
            return
        if len(data) != JTAGD_LENGTH:
            raise Exception('Wrong JTAG data length')
        ppcInstrEncoding = data[1:]
        bytes_data = [int(ppcInstrEncoding[0:8], 2), int(ppcInstrEncoding[8:16], 2), int(ppcInstrEncoding[16:24], 2), int(ppcInstrEncoding[24:32], 2)]
        md = Cs(CS_ARCH_PPC, CS_MODE_32 + CS_MODE_BIG_ENDIAN)
        md.detail = True
        dis = md.disasm(bytes(bytes_data), 0x1000)
        instr = dis.__next__()
        disassembled = "%s %s" % (instr.mnemonic, instr.op_str)
        print('PPCINST: %s' % disassembled)
        self.decoder.put(self.decoder.ss, self.decoder.es, self.decoder.out_ann, [0, [disassembled]])

    def tdo(self, data):
        if data == "000000000000000000000000000000001":
            return
        if data == "00000000000000000000000000000001":
            return
        if data == "00000000000000000000000000000000":
            return
        if data == '00000000000100000000000000000000': #weird shit???
            return
        if data == '00000000000100000000000010000000': #weird shit???
            return
        import ipdb; ipdb.set_trace()
        raise Exception("Unexpected DR TDO value")


class PPCDBGR(JTAGInstruction):
    def __init__(self, decoder):
        self.decoder = decoder

    def tdi(self, data):
        self.i = int(data, 2)

    def tdo(self, data):
        self.o = int(data, 2)
        print("DBGR IN: 0x%x OUT: 0x%x" % (self.i, self.o))
        self.decoder.put(self.decoder.ss, self.decoder.es, self.decoder.out_ann, [1, ["DBGR: 0x%x / 0x%x" % (self.i, self.o)]])



class Decoder(srd.Decoder):
    api_version = 3
    id = 'jtag_ppc'
    name = 'JTAG/PPC'
    longname = 'JTAG / PowerPC(BDM)'
    desc = 'PowerPC Background Debug Mode JTAG protocol'
    license = 'mit'
    inputs = ['jtag']
    outputs = []
    tags = ['Debug/trace']
    annotations = (
            ('ppcinst', 'PPCINST'),
            ('ppcdbgr', 'PPCDBGR'),
    )
    annotation_rows = (
            ('ppc', 'PowerPC', (0,1)),
    )

    JTAG_Instructions = {
        #JTAG PPCMODE instruction code (Used to set JTAG debug mode)
        "01010100" : PPCMODE,
        #JTAG PPCINST instruction code (Used to run PPC instructions presented in data words)
        "01110100" : PPCINST,
        #JTAG PPCDBGR instruction code (Used to read and write to the DEBUG special register)
        "10110100" : PPCDBGR,
        #standard JTAG instructions
        "11111111" : BYPASS
    }

    def __init__(self):
        self.reset()

    def reset(self):
        self.jtagInstruction = None

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def decode(self, ss: int, es: int, data):
        cmd, val = data
        self.ss, self.es = ss, es

        if cmd == 'NEW STATE':
            return
        
        # Enter new JTAG Instruction
        if cmd == 'IR TDI':
            if len(val[0]) != JTAGI_LENGTH:
                raise Exception('Wrong JTAG instruction length')
            if val[0] in self.JTAG_Instructions:
                self.jtagInstruction = self.JTAG_Instructions[val[0]](self)
                return
            else:
                # Unknown JTAG instruction
                import ipdb; ipdb.set_trace()

        # Not very informative; just check TDO is the expected constant
        if cmd == 'IR TDO':
            if val[0] != "00000001":
                raise Exception('Unexpected IR TDO value')
            return

        if cmd == 'DR TDI':
            return self.jtagInstruction.tdi(val[0])

        if cmd == 'DR TDO':
            return self.jtagInstruction.tdo(val[0])

        raise Exception("Something other than IR/DR TDI/TDO")
