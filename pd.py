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
        # DBCR0 bit-fields
        i = "%s ++ " % data[32]
        if self.i == 0:
            i = i + '0'
        if self.i & 0x80000000:
            i = i + 'EDM '
        if self.i & 0x40000000:
            i = i + 'IDM '
        if (self.i & 0x30000000) == 0x20000000:
            i = i + 'RST[chip] '
        if (self.i & 0x30000000) == 0x10000000:
            i = i + 'RST[core] '
        if (self.i & 0x30000000) == 0x30000000:
            i = i + 'RST[system] '
        if self.i & 0x8000000:
            i = i + 'ICMP '
        if self.i & 0x4000000:
            i = i + 'BRT '
        if self.i & 0x2000000:
            i = i + 'IRPT '
        if self.i & 0x1000000:
            i = i + 'TRAP '
        if self.i & 0x800000:
            i = i + 'IAC1 '
        if self.i & 0x400000:
            i = i + 'IAC2 '
        if self.i & 0x200000:
            i = i + 'IAC3 '
        if self.i & 0x100000:
            i = i + 'IAC4 '
        if self.i & 0x80000:
            i = i + 'DAC1R '
        if self.i & 0x40000:
            i = i + 'DAC1W '
        if self.i & 0x20000:
            i = i + 'DAC2R '
        if self.i & 0x10000:
            i = i + 'DAC2W '
        if self.i & 0x8000:
            i = i + 'RET '
        if self.i & 0x7FFE:
            i = i + 'Reserved '
        if self.i & 0x1:
            i = i + 'FT '
        print("PPCMODE: %s -> 0x%x" % (i, self.o))
        self.decoder.put(self.decoder.ss, self.decoder.es, self.decoder.out_ann, [1, ["PPCMODE: %s -> 0x%x" % (i, self.o)]])

# from A2 Processor User's Manual, Table 14-1
SPRs_A2 = {
    # sheet 1
    31   :  'ACOP',
    913  :  'AESR',
    1008 :  'CCR0',
    1009 :  'CCR1',
    1010 :  'CCR2',
    1013 :  'CCR3',
    912  :  'CESR',
    58   :  'CSRR0',
    59   :  'CSRR1',
    9    :  'CTR',
    316  :  'DAC1',
    317  :  'DAC2',
    849  :  'DAC3',
    850  :  'DAC4',
    308  :  'DBCR0',
    309  :  'DBCR1',
    310  :  'DBCR2',
    848  :  'DBCR3',
    304  :  'DBSR',
    306  :  'DBSRWR',
    61   :  'DEAR',
    22   :  'DEC',
    54   :  'DECAR',
    318  :  'DVC1',
    319  :  'DVC2',
    # sheet 2
    307  :  'EPCR',
    947  :  'EPLC',
    948  :  'EPSC',
    350  :  'EPTCFG',
    62   :  'ESR',
    381  :  'GDEAR',
    383  :  'GESR',
    447  :  'GIVPR',
    382  :  'GPIR',
    368  :  'GSPRG0',
    369  :  'GSPRG1',
    370  :  'GSPRG2',
    371  :  'GSPRG3',
    378  :  'GSRR0',
    379  :  'GSRR1',
    351  :  'HACOP',
    312  :  'IAC1',
    313  :  'IAC2',
    314  :  'IAC3',
    315  :  'IAC4',
    882  :  'IAR',
    914  :  'IESR1',
    915  :  'IESR2',
    880  :  'IMMR',
    #we omit IMPDEP regions for now
    880  :  'IMR',
    1011 :  'IUCR0',
    883  :  'IUCR1',
    # sheet 3
    884  :  'IUCR2',
    888  :  'IUDBG0',
    889  :  'IUDBG1',
    890  :  'IUDBG2'
    #...

}

# from PPC440 Processor User's Manual, Table 9-1 (p.403 et seq in r1.09)
SPRs_PPC440 = {
    0x001 :  'XER',
    0x008 :  'LR',
    0x009 :  'CTR',
    0x016 :  'DEC',
    0x01A :  'SRR0',
    0x01B :  'SRR1',
    0x030 :  'PID',
    0x036 :  'DECAR',
    0x03A :  'CSRR0',
    0x03B :  'CSRR1',
    0x03D :  'DEAR',
    0x03E :  'ESR',
    0x03F :  'IVPR',
    0x100 :  'USPRG0',
# p.404
    0x101 :  'USPRG1', # corrected: this seems to be an error in the 440 UM
    0x102 :  'USPRG2',
    0x103 :  'USPRG3',
    0x104 :  'USPRG4',
    0x105 :  'USPRG5',
    0x106 :  'USPRG6',
    0x107 :  'USPRG7',
    0x10C :  'UTBL',
    0x10D :  'UTBU',
    0x110 :  'SPRG0',
    0x111 :  'SPRG1',
    0x112 :  'SPRG2',
    0x113 :  'SPRG3',
    0x114 :  'SPRG4',
    0x115 :  'SPRG5',
    0x116 :  'SPRG6',
    0x117 :  'SPRG7',
    0x11C :  'TBL',
    0x11D :  'TBU',
    0x11E :  'PIR',
    0x11F :  'PVR',
    0x130 :  'DBSR',
    0x134 :  'DBCR0',
    0x135 :  'DBCR1',
    0x136 :  'DBCR2',
    0x138 :  'IAC1',
    0x139 :  'IAC2',
    0x13A :  'IAC3',
    0x13B :  'IAC4',
    0x13C :  'DAC1',
    0x13D :  'DAC2',
    0x13E :  'DAC3',
    0x13F :  'DAC4',
    0x150 :  'TSR',
    0x154 :  'TCR',
    0x190 :  'IVOR',
    0x191 :  'IVOR',
    0x192 :  'IVOR',
    0x193 :  'IVOR',
    0x194 :  'IVOR',
    0x195 :  'IVOR',
# p.405
    0x196 :  'IVOR6',
    0x197 :  'IVOR7',
    0x198 :  'IVO8R',
    0x199 :  'IVOR9',
    0x19A :  'IVOR10',
    0x19B :  'IVOR11',
    0x19C :  'IVOR12',
    0x19D :  'IVOR13',
    0x19E :  'IVOR14',
    0x19F :  'IVOR15',
    0x23A :  'MCSRR0',
    0x23B :  'MCSRR1',
    0x23C :  'MCSR',
    0x370 :  'INV0',
    0x371 :  'INV1',
    0x372 :  'INV2',
    0x373 :  'INV3',
    0x374 :  'ITV0',
    0x375 :  'ITV1',
    0x376 :  'ITV2',
    0x377 :  'ITV3',
    0x378 :  'CCR1',
    0x390 :  'DNV0',
    0x391 :  'DNV1',
    0x392 :  'DNV2',
    0x393 :  'DNV3',
    0x394 :  'DTV0',
    0x395 :  'DTV1',
    0x396 :  'DTV2',
    0x397 :  'DTV3',
    0x398 :  'DVLIM',
    0x399 :  'IVLIM',
    0x39B :  'RSTCFG',
    0x39C :  'DCDBTL',
    0x39D :  'DCDBTH',
    0x39E :  'ICDBTRL',
    0x39F :  'ICDBTRH',
    0x3B2 :  'MMUCR',
# p.406
    0x3B3 :  'CCR0',
    0x3D3 :  'ICDBDR',
    0x3F3 :  'DBDR'
}

# This shold be handled automatically in the future
SPRs = SPRs_PPC440

class PPCINST(JTAGInstruction):
    def __init__(self, decoder):
        self.decoder = decoder

    def tdi(self, data):
        self.i = int(data, 2)
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
        if instr.mnemonic=='mtspr':
            if instr.op_find(1,0).reg in SPRs:
                disassembled = disassembled + '  (' + SPRs[instr.op_find(1,0).reg] + ')'
        if instr.mnemonic=='mfspr':
            spr = instr.op_find(CS_OP_IMM, 1).reg
            if spr in SPRs:
                disassembled = disassembled + '  (' + SPRs[spr] + ')'
        print('PPCINST: %s' % disassembled)
        self.decoder.put(self.decoder.ss, self.decoder.es, self.decoder.out_ann, [0, [disassembled]])

    def tdo(self, data):
        if self.i == 0:
            o = "PPCINST? 0x%x" % int(data, 2)
            self.decoder.put(self.decoder.ss, self.decoder.es, self.decoder.out_ann, [0, [o]])
        return


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
