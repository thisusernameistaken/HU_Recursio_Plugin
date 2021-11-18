from binaryninja import Architecture, Endianness, InstructionInfo, RegisterInfo,CallingConvention, IntrinsicInfo, Type
from .disassembly import RecursoDisassembler
from .callingConvention import ReccCallingConvention
from .lifter import RecursoLifter

class Recurso(Architecture):
    name = "recurso"
    endianness = Endianness.BigEndian

    default_int_size = 8
    address_size = 8
    max_isntruction_length = 9
    # this is dumb
    # max_isntruction_length = 50
    instr_alignment = 1

    regs = {
        "r0":RegisterInfo('r0',8),
        "r1":RegisterInfo('r1',8),
        "r2":RegisterInfo('r2',8),
        "r3":RegisterInfo('r3',8),
        "r4":RegisterInfo('r4',8),
        "r5":RegisterInfo('r5',8),
        "r6":RegisterInfo('r6',8),
        "r7":RegisterInfo('r7',8),
        "r8":RegisterInfo('r8',8),
        "r9":RegisterInfo('r9',8),
        "r10":RegisterInfo('r10',8),
        "r11":RegisterInfo('r11',8),
        "r12":RegisterInfo('r12',8),
        "r13":RegisterInfo('r13',8),
        "ret":RegisterInfo('ret',8),
        "pc":RegisterInfo("pc",8),
        "sp":RegisterInfo("sp",8)
    }

    intrinsics = {
        'input':IntrinsicInfo([Type.int(8)],[Type.int(8)]),
        "print":IntrinsicInfo([Type.int(8)],[])
    }

    stack_pointer = "sp"

    def __init__(self):
        self.disassembler = RecursoDisassembler(self)
        self.lifter = RecursoLifter(self)
        super().__init__()

    def get_bytes(self,addr):
        while not self.disassembler.update_bv():
            pass
        return self.disassembler.bv.read(addr,0x60)

    def get_instruction_info(self,data,addr):
        b = self.get_bytes(addr)
        disas,length,cond = self.disassembler.disassemble(data,b)
        result = InstructionInfo()
        result.length = length
        if cond != None:
            if len(cond)>1 and len(cond)<3:
                result.add_branch(cond[0],cond[1])
            elif len(cond)>2:
                result.add_branch(cond[0],addr+cond[1])
                result.add_branch(cond[2],addr+cond[3])
            else:
                result.add_branch(cond[0])
        return result
    
    def get_instruction_text(self,data,addr):
        b = self.get_bytes(addr)
        disas = self.disassembler.disassemble(data,b)
        return disas

    def get_instruction_low_level_il(self,data,addr,il):
        b = self.get_bytes(addr)
        length = self.lifter.lift(data,addr,il,b)
        return length