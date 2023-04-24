import ida_bytes
import numpy as np

#TODO this becomes a class


def disp24(op1, disp24):
    # Flip the lower two bytes of disp24
    disp24 = (disp24 & 0xff0000) | ((disp24 & 0xff) << 8) | (
        (disp24 >> 8) & 0xff)
    opcode = ((op1 & 0xFF) << 24) + disp24
    # Pack the bytes into an array
    return opcode


def call(current_ea, target_ea):
    disp24_val = target_ea - current_ea
    disp24_val = (disp24_val >> 1) & 0xFFFFFF
    return disp24(0x6D, disp24_val)


def patch_call(current_ea, target_ea):
    return ida_bytes.patch_bytes(current_ea,
                                 (call(current_ea,
                                       target_ea)).to_bytes(4, 'big'))


# Test code
if __name__ == "__main__":

    op1 = int(0x6d)
    disp2_value = 0xabcdef

    result = disp24(op1, disp2_value)
    current_ea = 0x80000412
    target_ea = 0x80001000
    res = call(current_ea, target_ea)

    print((res))