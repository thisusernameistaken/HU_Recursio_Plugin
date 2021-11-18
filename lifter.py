from binaryninja import LowLevelILLabel, ILRegister, Architecture
from .disassembly import RecursoDisassembler

class RecursoLifter:

    def __init__(self,arch):
        self.arch = arch
        self.disassembler = RecursoDisassembler(arch)

    def jump_cond(self,il,cond,target,addr,base):
        true_label = il.get_label_for_address(Architecture['recurso'], base+target)
        false_label = il.get_label_for_address(Architecture['recurso'], base+addr)
        
        mark_true = False
        if true_label is None:
            true_label = LowLevelILLabel()
            # mark_true = True
        mark_false = False
        if false_label is None:
            false_label = LowLevelILLabel()
            # mark_false = True        

        ils=[]
        ils.append(il.if_expr(cond, true_label, false_label))
        if mark_true:
            il.mark_label(true_label)
            ils.append(il.jump(il.const(8,base+addr)))
        if mark_false:
            il.mark_label(false_label)
            ils.append(il.jump(il.const(8,base+target)))
        # print(ils)
        return ils

    def _lift_cond(self,cond, insn_length, addr, base,il):
        """Helper for lifting conditional jumps
        
        We pass in an IL condition (LowLevelILExpr) and this function lifts a IL
        conditional that will jump to `insn.target_offset(addr)` if the condition is
        true, otherwise we continue to the next instruction.
        """
        true_label = il.get_label_for_address(Architecture['recurso'],
                                            addr+base)
        false_label = il.get_label_for_address(Architecture['recurso'],
                                            base + insn_length)
        # true_label = None
        # false_label = None
        must_mark_true = False
        if true_label is None:
            true_label = LowLevelILLabel()
            must_mark_true = True

        must_mark_false = False
        if false_label is None:
            false_label = LowLevelILLabel()
            must_mark_false = True

        il.append(
            il.if_expr(cond,
                    false_label,
                    true_label
                    ))
        if must_mark_true:
            il.mark_label(true_label)
            il.append(il.jump(il.const_pointer(8, addr+base)))
        if must_mark_false:
            il.mark_label(false_label)
            il.append(il.jump(il.const_pointer(8, insn_length+base)))
        return insn_length

    def lift(self,data,addr,il,b):
        while not self.disassembler.update_bv():
            pass
        disas_info,nmem = self.disassembler.get_disas_info(data,b)
        if nmem == "LOAD":
            # load what is in register to stack
            reg  = disas_info['register']
            if int(reg[1:]) < 12:
                reg = il.reg(8,reg)
                il.append(il.push(8,reg))
        elif nmem == "AND":
            a = il.pop(8)
            b = il.pop(8)
            s = il.and_expr(8,a,b)
            il.append(il.push(8,s))
        elif nmem == "OR":
            a = il.pop(8)
            b = il.pop(8)
            s = il.or_expr(8,a,b)
            il.append(il.push(8,s))
        elif nmem == "XOR":
            a = il.pop(8)
            b = il.pop(8)
            s = il.xor_expr(8,a,b)
            il.append(il.push(8,s))
        elif nmem == "ICONST":
            val = il.const(8,disas_info['value'])
            il.append(il.push(8,val))
        elif nmem == "STORE":
            # store what is on the stack to register
            reg = disas_info['register']
            if int(reg[1:]) < 12:
                # sp = il.reg(8,"sp")
                stack_val = il.pop(8)
                il.append(il.set_reg(8,reg,stack_val))
                # il.append(il.pop(sp))
        elif nmem == "CALL":
                dest = il.const_pointer(8,disas_info['condition'][1])
                # sp = il.reg(8,"sp")
                # il.append(il.load(8,sp))
                il.append(il.call(dest))
                il.append(il.push(8,il.reg(8,"ret")))
        elif nmem == "NCMP":
            arg1 = il.pop(8)
            arg2 = il.pop(8)
            cond = il.compare_not_equal(8,arg1,arg2)
            for i in range(len(b)):
                if b[i] == 0x0e:
                    break
            target = i+1
            return self._lift_cond(cond,1,target,addr,il)
        elif nmem == "LTCMP":
            arg1 = il.pop(8)
            arg2 = il.pop(8)
            cond = il.compare_unsigned_less_than(8,arg1,arg2)
            for i in range(len(b)):
                if b[i] == 0x0e:
                    break
            target = i+1
            return self._lift_cond(cond,1,target,addr,il)
        elif nmem == "GTCMP":
            arg1 = il.pop(8)
            arg2 = il.pop(8)
            cond = il.compare_unsigned_greater_than(8,arg1,arg2)
            for i in range(len(b)):
                if b[i] == 0x0e:
                    break
            target = i+1
            return self._lift_cond(cond,1,target,addr,il)
        elif nmem == "CMP":
            arg1 = il.pop(8)
            arg2 = il.pop(8)
            cond = il.compare_equal(8,arg1,arg2)
            for i in range(len(b)):
                if b[i] == 0x0e:
                    break
            target = i+1
            return self._lift_cond(cond,1,target,addr,il)
        elif nmem == "INPUT":
            sp = il.load(8,il.reg(8,"sp"))
            # arg1_addr = il.sub(8,sp,il.const(8,8))
            il.append(il.intrinsic([],'input',[sp]))
        elif nmem == "PRINT":
            sp = il.pop(8)
            il.append(il.intrinsic([],'print',[sp]))
        elif nmem == "RET":
            arg1 = il.pop(8)
            il.append(il.set_reg(8,"ret",arg1))
            # il.append(il.ret(0))
            il.append(il.ret(arg1))
        elif nmem == "HALT":
            il.append(il.no_ret())
        elif nmem == "ISUB":
            a = il.pop(8)
            b = il.pop(8)
            s = il.sub(8,a,b)
            il.append(il.push(8,s))
        elif nmem == "IMUL":
            a = il.pop(8)
            b = il.pop(8)
            s = il.mult(8,a,b)
            il.append(il.push(8,s))
        elif nmem == "IDIV":
            a = il.pop(8)
            b = il.pop(8)
            s = il.div_signed(8,a,b)
            il.append(il.push(8,s)) 
        elif nmem == "IADD":
            a = il.pop(8)
            b = il.pop(8)
            s = il.add(8,a,b)
            il.append(il.push(8,s))       
        else:
            il.append(il.nop())
        return disas_info['length']