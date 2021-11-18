from binaryninja import InstructionTextToken, InstructionInfo
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninjaui import UIContext
import struct


class RecursoDisassembler:

    def __init__(self,arch):
        self.arch = arch
        self.bv = None
        self.OPCODES = [
            {"nmem":"NOP","func":self.nop},
            {"nmem":"ISUB","func":self.nop},
            {"nmem":"IMUL","func":self.nop},
            {"nmem":"IADD","func":self.nop},
            {"nmem":"FADD","func":self.nop},
            {"nmem":"NOP","func":self.nop},
            {"nmem":"NOP","func":self.nop},
            {"nmem":"NOP","func":self.nop},
            {"nmem":"ICONST","func":self.iconst},
            {"nmem":"NOP","func":self.nop},
            {"nmem":"NOP","func":self.nop},
            {"nmem":"STORE","func":self.store},
            {"nmem":"LOAD","func":self.load},
            {"nmem":"HALT","func":self.ret},
            {"nmem":"RET","func":self.ret},
            {"nmem":"PRINT","func":self.nop},
            {"nmem":"POP","func":self.nop},
            {"nmem":"NOP","func":self.nop},
            {"nmem":"NOP","func":self.nop},
            {"nmem":"LDIV","func":self.nop},
            {"nmem":"NOP","func":self.nop},
            {"nmem":"CALL","func":self.call},
            {"nmem":"INPUT","func":self._input},
            {"nmem":"CMP","func":self._cmp},
            {"nmem":"OR","func":self.nop},
            {"nmem":"AND","func":self.nop},
            {"nmem":"XOR","func":self.nop},
            {"nmem":"NCMP","func":self.ncmp},
            {"nmem":"LTCMP","func":self._cmp},
            {"nmem":"GTCMP","func":self.ncmp}
        ]
    
    def nop(self,d,b):
        data = {}
        data['length']=1
        return data

    def load(self,d,b):
        data = {}
        data['length']=5
        reg = d[1:5]
        register = struct.unpack(">I",reg)[0]
        register = f"r{register}"
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, ' '),InstructionTextToken(InstructionTextTokenType.RegisterToken,register)]
        data["tokens"] = tokens
        data['register'] = register
        return data

    def store(self,d,b):
        data = {}
        data['length']=5
        reg = d[1:5]
        register = struct.unpack(">I",reg)[0]
        register = f"r{register}"
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, ' '),InstructionTextToken(InstructionTextTokenType.RegisterToken,register)]
        data["tokens"] = tokens
        data['register'] = register
        return data

    def call(self,d,b):
        data = {}
        data['length']=5
        dest = d[1:5]
        dest_index = struct.unpack(">I",dest)[0]
        if self.bv != None:
            name = self.bv.functions[dest_index].name
            func = self.bv.functions[dest_index]
            tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, ' '),InstructionTextToken(InstructionTextTokenType.CodeSymbolToken,name,func.start)]
            data["tokens"] = tokens
            data['condition'] = [BranchType.CallDestination,func.start]
        return data

    def _input(self,d,b):
        data = {}
        data['length']=1
        return data

    def iconst(self,d,b):
        data={}
        data['length'] = 9
        val = d[1:9]
        value = struct.unpack(">Q",val)[0]
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, ' '),InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(value),value)]
        data["tokens"] = tokens
        data['value'] = value
        return data

    def _cmp(self,d,b):
        data={}
        data['length'] = 1
        for i in range(len(b)):
            if b[i] == 0x0e:
                break
        data['condition'] = [BranchType.TrueBranch,1,BranchType.FalseBranch,i+1]
        return data

    def ncmp(self,d,b):
        data={}
        data['length'] = 1
        for i in range(len(b)):
            if b[i] == 0x0e:
                break
        data['condition'] = [BranchType.FalseBranch,1,BranchType.TrueBranch,i+1]
        return data

    def ret(self,d,b):
        data = {}
        data['length']=1
        data['condition'] = [BranchType.FunctionReturn]
        return data
    
    def get_disas_info(self,data,b):
        opcode = data[0]
        if opcode < len(self.OPCODES):
            op_dict = self.OPCODES[opcode]
            disas_info = op_dict['func'](data,b)
            return disas_info,op_dict['nmem']
        else:
            return None,None

    def update_bv(self):
        if self.bv == None:
            ac = UIContext.activeContext()
            cv=ac.getCurrentViewFrame()
            if cv != None:
                self.bv = cv.getCurrentBinaryView()
                if self.bv != None:
                    return True
                return False
            return False
        return True

    def disassemble(self,data,b):
        # try:
            disas_info,nmem = self.get_disas_info(data,b)
            length = disas_info['length']
            if "condition" in disas_info.keys():
                cond = disas_info['condition']
            else:
                cond = None
            tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, nmem)]
            if "tokens" in disas_info.keys():
                tokens.extend(disas_info['tokens'])
            return tokens,length,cond
        # except:
        #     tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, "NOP")]
        #     return tokens,1,None