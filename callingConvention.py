from binaryninja import CallingConvention

class ReccCallingConvention(CallingConvention):
    name = "recc_cc"
    int_return_reg = 'ret'
    int_arg_regs = []#["r0","r1","r2"]
    stack_adjusted_on_return = False
    # TODO: finish