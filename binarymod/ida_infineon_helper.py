import ida_bytes
import idaapi
import binascii
import numpy as np

#TODO this becomes a class

endianness = 'little'




def op_from_ABS_format(op1, op2, off18, s1d):
    opcode = (op1 & 0xFF) << 24
    opcode |= (op2 & 0x3) << 26
    opcode |= (off18 & 0x3FFFF) << 2
    opcode |= (s1d & 0xF) << 8
    return opcode

def op_from_ABSB_format(op1, off18, op2, b, bpos):
    opcode = (op1 & 0xFF) << 24
    opcode |= (off18 & 0x3FFFF) << 4
    opcode |= (op2 & 0x3) << 26
    opcode |= (b & 0x1) << 11
    opcode |= (bpos & 0x7) << 8
    return opcode

def op_from_B_format(op1, disp24):
    # Flip the lower two bytes of disp24
    disp24_field = (disp24 & 0xff0000) >> 8 
    disp24_field |= (disp24 & 0xffff) << 16
    opcode = op1 + disp24_field
    # convert to bytes
    opcode = (opcode).to_bytes(4, endianness)    
    return opcode

def op_from_BIT_format(op1, D, pos2, op2, pos1, S2, S1):
    
    opcode |= (D & 0xF) << 28
    opcode |= (pos2 & 0x1F) << 23
    opcode |= (op2 & 0x3) << 21
    opcode |= (pos1 & 0x1F) << 16
    opcode |= (S2 & 0xF) << 12
    opcode |= (S1 & 0xF) << 8
    opcode |= (op1 & 0xFF)
    # convert to bytes
    opcode = (opcode).to_bytes(4, endianness)    
    return opcode

def op_from_BO_format(op1, off10, op2, s1, s2):
    # Extract fields from the opcode
    off10_field = (off10 & 0x3F) << 16
    off10_field |= (off10 & 0x3C0) << 22
    op2_field = (op2 & 0x3F) << 22
    s2_field = (s2 & 0xF) << 12
    s1d_field = (s1 & 0xF) << 8
    # Combine the fields to form the opcode
    opcode = op1 | s2_field | s1d_field | op2_field| off10_field
    # convert to bytes
    opcode = (opcode).to_bytes(4, endianness)
    return opcode




def op_from_BOL_format(op1, off16, s1, s2):
    # Extract fields from the opcode
    off16_field = (off16 & 0x3F) << 16
    off16_field |= (off16 & 0x3C0) << 22
    off16_field |= (off16 & 0xFC00)  << 12
    s2_field = (s2 & 0xF) << 12
    s1d_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = (op1 ) | s2_field | s1d_field | off16_field
    # convert to bytes
    opcode = (opcode).to_bytes(4, endianness)

    return opcode





def op_from_BRC_format(op1, op2, disp15, const4, s1):
    # Extract fields from the opcode
    op1_field = (op1 & 0xFF) << 24
    op2_field = (op2 & 0x1) << 31
    disp15_field = (disp15 & 0x7FFF) << 16
    const4_field = (const4 & 0xF) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | op2_field | disp15_field | const4_field | s1_field

    return opcode

# op1: The first operand of the instruction.
# op2: The second operand of the instruction.
# disp15: The 15-bit displacement.
# n: The 5-bit condition code.
# s1: The 4-bit shift amount.
def op_from_BRN_format(op1, op2, disp15, n, s1):
    # Extract fields from the opcode
    op1_field = (op1 & 0xFF) << 24
    op2_field = (op2 & 0x1) << 31
    disp15_field = (disp15 & 0x7FFF) << 16
    n_field = (n & 0x1F) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | op2_field | disp15_field | n_field | s1_field

    return opcode

"""
This function takes five arguments:

* op1: The first operand of the instruction.
* op2: The second operand of the instruction.
* disp15: The 15-bit displacement.
* s2: The 4-bit shift amount.
* s1: The 4-bit shift amount.

The function returns the opcode for the BRR format.
"""

def op_from_BRR_format(op1, op2, disp15, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The op2_field is the 9th bit of the opcode.
    The disp15_field is the 16th to 30th bits of the opcode.
    The s2_field is the 12th to 15th bits of the opcode.
    The s1_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    op2_field = (op2 & 0x1) << 31
    disp15_field = (disp15 & 0x7FFF) << 16
    s2_field = (s2 & 0xF) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | op2_field | disp15_field | s2_field | s1_field

    return opcode

"""
This function takes four arguments:

* op1: The first operand of the instruction.
* op2: The second operand of the instruction.
* const9: The 9-bit constant.
* s1: The 4-bit shift amount.

The function returns the opcode for the RC format.
"""

def op_from_RC_format(op1, op2, const9, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The op2_field is the 9th to 20th bits of the opcode.
    The const9_field is the 21st to 29th bits of the opcode.
    The s1_field is the 30th to 31st bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    op2_field = (op2 & 0x1F) << 21
    const9_field = (const9 & 0x1FF) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | op2_field | const9_field | s1_field

    return opcode
"""
This function takes six arguments:

* op1: The first operand of the instruction.
* pos: The 5-bit position.
* op2: The 2-bit operand 2.
* width: The 5-bit width.
* const4: The 4-bit constant.
* s1: The 4-bit shift amount.

The function returns the opcode for the RCPW format.
"""

def op_from_RCPW_format(op1, pos, op2, width, const4, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The pos_field is the 23rd to 27th bits of the opcode.
    The op2_field is the 21st to 22nd bits of the opcode.
    The width_field is the 16th to 20th bits of the opcode.
    The const4_field is the 12th to 15th bits of the opcode.
    The s1_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    pos_field = (pos & 0x1F) << 23
    op2_field = (op2 & 0x3) << 21
    width_field = (width & 0x1F) << 16
    const4_field = (const4 & 0xF) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | pos_field | op2_field | width_field | const4_field | s1_field

    return opcode

"""
This function takes five arguments:

* op1: The first operand of the instruction.
* s3: The 3-bit shift amount.
* op2: The 2-bit operand 2.
* const4: The 4-bit constant.
* s1: The 4-bit shift amount.

The function returns the opcode for the RCRR format.
"""

def op_from_RCRR_format(op1, s3, op2, const4, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s3_field is the 24th to 27th bits of the opcode.
    The op2_field is the 21st to 23rd bits of the opcode.
    The const4_field is the 12th to 15th bits of the opcode.
    The s1_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    s3_field = (s3 & 0x7) << 24
    op2_field = (op2 & 0x3) << 21
    const4_field = (const4 & 0xF) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | s3_field | op2_field | const4_field | s1_field

    return opcode
"""
This function takes six arguments:

* op1: The first operand of the instruction.
* s3: The 3-bit shift amount.
* op2: The 2-bit operand 2.
* width: The 5-bit width.
* const4: The 4-bit constant.
* s1: The 4-bit shift amount.

The function returns the opcode for the RCRW format.
"""

def op_from_RCRW_format(op1, s3, op2, width, const4, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s3_field is the 24th to 27th bits of the opcode.
    The op2_field is the 21st to 23rd bits of the opcode.
    The width_field is the 16th to 20th bits of the opcode.
    The const4_field is the 12th to 15th bits of the opcode.
    The s1_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    s3_field = (s3 & 0x7) << 24
    op2_field = (op2 & 0x3) << 21
    width_field = (width & 0x1F) << 16
    const4_field = (const4 & 0xF) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | s3_field | op2_field | width_field | const4_field | s1_field

    return opcode
"""
This function takes four arguments:

* op1: The first operand of the instruction.
* const16: The 16-bit constant.
* s1: The 4-bit shift amount.

The function returns the opcode for the RLC format.
"""

def op_from_RLC_format(op1, const16, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The const16_field is the 12th to 27th bits of the opcode.
    The s1_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    const16_field = (const16 & 0xFFFF) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | const16_field | s1_field

    return opcode
"""
This function takes five arguments:

* op1: The first operand of the instruction.
* op2: The 8-bit operand 2.
* n: The 1-bit shift direction.
* s2: The 3-bit shift amount.
* s1: The 4-bit shift amount.

The function returns the opcode for the RR format.
"""

def op_from_RR_format(op1, op2, n, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The op2_field is the 9th to 16th bits of the opcode.
    The n_field is the 17th bit of the opcode.
    The s2_field is the 18th to 20th bits of the opcode.
    The s1_field is the 21st to 24th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    op2_field = (op2 & 0xFF) << 16
    n_field = (n & 0x1) << 17
    s2_field = (s2 & 0x7) << 18
    s1_field = (s1 & 0xF) << 21

    # Combine the fields to form the opcode
    opcode = op1_field | op2_field | n_field | s2_field | s1_field

    return opcode
"""
This function takes five arguments:

* op1: The first operand of the instruction.
* op2: The 8-bit operand 2.
* n: The 1-bit shift direction.
* s2: The 3-bit shift amount.
* s1: The 4-bit shift amount.

The function returns the opcode for the RR1 format.
"""

def op_from_RR1_format(op1, op2, n, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The op2_field is the 9th to 16th bits of the opcode.
    The n_field is the 17th bit of the opcode.
    The s2_field is the 18th to 20th bits of the opcode.
    The s1_field is the 21st to 24th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    op2_field = (op2 & 0xFF) << 16
    n_field = (n & 0x1) << 17
    s2_field = (s2 & 0x7) << 18
    s1_field = (s1 & 0xF) << 21

    # Combine the fields to form the opcode
    opcode = op1_field | op2_field | n_field | s2_field | s1_field

    return opcode
"""
This function takes four arguments:

* op1: The first operand of the instruction.
* op2: The 8-bit operand 2.
* s2: The 3-bit shift amount.
* s1: The 4-bit shift amount.

The function returns the opcode for the RR2 format.
"""

def op_from_RR2_format(op1, op2, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The op2_field is the 9th to 16th bits of the opcode.
    The s2_field is the 18th to 20th bits of the opcode.
    The s1_field is the 21st to 24th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    op2_field = (op2 & 0xFF) << 16
    s2_field = (s2 & 0x7) << 18
    s1_field = (s1 & 0xF) << 21

    # Combine the fields to form the opcode
    opcode = op1_field | op2_field | s2_field | s1_field

    return opcode

"""
This function takes six arguments:

* op1: The first operand of the instruction.
* pos: The 5-bit position.
* op2: The 2-bit operand 2.
* width: The 5-bit width.
* s2: The 3-bit shift amount.
* s1: The 4-bit shift amount.

The function returns the opcode for the RRPW format.
"""

def op_from_RRPW_format(op1, pos, op2, width, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The pos_field is the 23rd to 27th bits of the opcode.
    The op2_field is the 21st to 22nd bits of the opcode.
    The width_field is the 16th to 20th bits of the opcode.
    The s2_field is the 12th to 15th bits of the opcode.
    The s1_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    pos_field = (pos & 0x1F) << 23
    op2_field = (op2 & 0x3) << 21
    width_field = (width & 0x1F) << 16
    s2_field = (s2 & 0x7) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | pos_field | op2_field | width_field | s2_field | s1_field

    return opcode

"""
This function takes six arguments:

* op1: The first operand of the instruction.
* s3: The 3-bit shift amount.
* op2: The 2-bit operand 2.
* n: The 1-bit shift direction.
* s2: The 3-bit shift amount.
* s1: The 4-bit shift amount.

The function returns the opcode for the RRR format.
"""

def op_from_RRR_format(op1, s3, op2, n, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s3_field is the 24th to 27th bits of the opcode.
    The op2_field is the 20th to 22nd bits of the opcode.
    The n_field is the 17th bit of the opcode.
    The s2_field is the 18th to 20th bits of the opcode.
    The s1_field is the 21st to 24th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    s3_field = (s3 & 0x7) << 24
    op2_field = (op2 & 0x3) << 20
    n_field = (n & 0x1) << 17
    s2_field = (s2 & 0x7) << 18
    s1_field = (s1 & 0xF) << 21

    # Combine the fields to form the opcode
    opcode = op1_field | s3_field | op2_field | n_field | s2_field | s1_field

    return opcode
"""
This function takes six arguments:

* op1: The first operand of the instruction.
* s3: The 3-bit shift amount.
* op2: The 2-bit operand 2.
* n: The 1-bit shift direction.
* s2: The 3-bit shift amount.
* s1: The 4-bit shift amount.

The function returns the opcode for the RRR1 format.
"""

def op_from_RRR1_format(op1, s3, op2, n, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s3_field is the 24th to 27th bits of the opcode.
    The op2_field is the 18th to 20th bits of the opcode.
    The n_field is the 17th bit of the opcode.
    The s2_field is the 18th to 20th bits of the opcode.
    The s1_field is the 21st to 24th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    s3_field = (s3 & 0x7) << 24
    op2_field = (op2 & 0x3) << 18
    n_field = (n & 0x1) << 17
    s2_field = (s2 & 0x7) << 18
    s1_field = (s1 & 0xF) << 21

    # Combine the fields to form the opcode
    opcode = op1_field | s3_field | op2_field | n_field | s2_field | s1_field

    return opcode
"""
This function takes five arguments:

* op1: The first operand of the instruction.
* s3: The 3-bit shift amount.
* op2: The 8-bit operand 2.
* s2: The 3-bit shift amount.
* s1: The 4-bit shift amount.

The function returns the opcode for the RRR2 format.
"""

def op_from_RRR2_format(op1, s3, op2, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s3_field is the 24th to 27th bits of the opcode.
    The op2_field is the 9th to 16th bits of the opcode.
    The s2_field is the 18th to 20th bits of the opcode.
    The s1_field is the 21st to 24th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    s3_field = (s3 & 0x7) << 24
    op2_field = (op2 & 0xFF) << 16
    s2_field = (s2 & 0x7) << 18
    s1_field = (s1 & 0xF) << 21

    # Combine the fields to form the opcode
    opcode = op1_field | s3_field | op2_field | s2_field | s1_field

    return opcode
"""
This function takes five arguments:

* op1: The first operand of the instruction.
* s3: The 3-bit shift amount.
* op2: The 2-bit operand 2.
* s2: The 3-bit shift amount.
* s1: The 4-bit shift amount.

The function returns the opcode for the RRRR format.
"""

def op_from_RRRR_format(op1, s3, op2, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s3_field is the 24th to 27th bits of the opcode.
    The op2_field is the 20th to 22nd bits of the opcode.
    The s2_field is the 18th to 20th bits of the opcode.
    The s1_field is the 21st to 24th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    s3_field = (s3 & 0x7) << 24
    op2_field = (op2 & 0x3) << 20
    s2_field = (s2 & 0x7) << 18
    s1_field = (s1 & 0xF) << 21

    # Combine the fields to form the opcode
    opcode = op1_field | s3_field | op2_field | s2_field | s1_field

    return opcode
"""
This function takes six arguments:

* op1: The first operand of the instruction.
* s3: The 3-bit shift amount.
* op2: The 2-bit operand 2.
* width: The 5-bit width.
* s2: The 3-bit shift amount.
* s1: The 4-bit shift amount.

The function returns the opcode for the RRRW format.
"""

def op_from_RRRW_format(op1, s3, op2, width, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s3_field is the 24th to 27th bits of the opcode.
    The op2_field is the 21st to 22nd bits of the opcode.
    The width_field is the 16th to 20th bits of the opcode.
    The s2_field is the 12th to 15th bits of the opcode.
    The s1_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    s3_field = (s3 & 0x7) << 24
    op2_field = (op2 & 0x3) << 21
    width_field = (width & 0x1F) << 16
    s2_field = (s2 & 0x7) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | s3_field | op2_field | width_field | s2_field | s1_field

    return opcode
"""
This function takes three arguments:

* op1: The 8-bit operand 1.
* op2: The 6-bit operand 2.
* s1d: The 3-bit shift amount and destination.

The function returns the opcode for the SYS format.
"""

def op_from_SYS_format(op1, op2, s1d):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The op2_field is the 22nd to 27th bits of the opcode.
    The s1d_field is the 19th to 21st bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 24
    op2_field = (op2 & 0x3F) << 22
    s1d_field = (s1d & 0x7) << 19

    # Combine the fields to form the opcode
    opcode = op1_field | op2_field | s1d_field

    return opcode

"""
This function takes two arguments:

* op1: The 8-bit opcode.
* disp8: The 8-bit displacement.

The function returns the opcode for the SB format.
"""

def op_from_SB_format(op1, disp8):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The disp8_field is the 8th to 15th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 8
    disp8_field = (disp8 & 0xFF) << 0

    # Combine the fields to form the opcode
    opcode = op1_field | disp8_field

    return opcode
"""
This function takes two arguments:

* op1: The 8-bit opcode.
* const4: The 4-bit constant.
* disp4: The 4-bit displacement.

The function returns the opcode for the SBC format.
"""

def op_from_SBC_format(op1, const4, disp4):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The const4_field is the 12th to 15th bits of the opcode.
    The disp4_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    const4_field = (const4 & 0xF) << 12
    disp4_field = (disp4 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | const4_field | disp4_field

    return opcode

"""
This function takes two arguments:

* op1: The 8-bit opcode.
* s2: The 2-bit shift amount.
* disp4: The 4-bit displacement.

The function returns the opcode for the SBR format.
"""

def op_from_SBR_format(op1, s2, disp4):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s2_field is the 12th to 13th bits of the opcode.
    The disp4_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    s2_field = (s2 & 0x3) << 12
    disp4_field = (disp4 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | s2_field | disp4_field

    return opcode
"""
This function takes two arguments:

* op1: The 8-bit opcode.
* n: The 4-bit constant.
* disp4: The 4-bit displacement.

The function returns the opcode for the SBRN format.
"""

def op_from_SBRN_format(op1, n, disp4):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The n_field is the 12th to 15th bits of the opcode.
    The disp4_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    n_field = (n & 0xF) << 12
    disp4_field = (disp4 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | n_field | disp4_field

    return opcode

"""
This function takes two arguments:

* op1: The 8-bit opcode.
* const8: The 8-bit constant.

The function returns the opcode for the SC format.
"""

def op_from_SC_format(op1, const8):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The const8_field is the 8th to 15th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    const8_field = (const8 & 0xFF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | const8_field

    return opcode

"""
This function takes two arguments:

* op1: The 8-bit opcode.
* s2: The 2-bit shift amount.
* d: The 4-bit displacement.

The function returns the opcode for the SLR format.
"""

def op_from_SLR_format(op1, s2, d):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s2_field is the 12th to 13th bits of the opcode.
    The d_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    s2_field = (s2 & 0x3) << 12
    d_field = (d & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | s2_field | d_field

    return opcode


"""
This function takes two arguments:

* op1: The 8-bit opcode.
* off4: The 4-bit offset.
* d: The 4-bit displacement.

The function returns the opcode for the SLRO format.
"""

def op_from_SLRO_format(op1, off4, d):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The off4_field is the 12th to 15th bits of the opcode.
    The d_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    off4_field = (off4 & 0xF) << 12
    d_field = (d & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | off4_field | d_field

    return opcode

"""
This function takes two arguments:

* op1: The 8-bit opcode.
* op2: The 2-bit operation.
* s1d: The 4-bit shift amount or displacement.

The function returns the opcode for the SR format.
"""

def op_from_SR_format(op1, op2, s1d):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The op2_field is the 12th to 13th bits of the opcode.
    The s1d_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    op2_field = (op2 & 0x3) << 12
    s1d_field = (s1d & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | op2_field | s1d_field

    return opcode

"""
This function takes two arguments:

* op1: The 8-bit opcode.
* const4: The 4-bit constant.
* s1d: The 4-bit shift amount or displacement.

The function returns the opcode for the SRC format.
"""

def op_from_SRC_format(op1, const4, s1d):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The const4_field is the 12th to 15th bits of the opcode.
    The s1d_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    const4_field = (const4 & 0xF) << 12
    s1d_field = (s1d & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | const4_field | s1d_field

    return opcode

"""
This function takes two arguments:

* op1: The 8-bit opcode.
* s2: The 2-bit shift amount.
* off4: The 4-bit offset.

The function returns the opcode for the SRO format.
"""

def op_from_SRO_format(op1, s2, off4):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s2_field is the 12th to 13th bits of the opcode.
    The off4_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    s2_field = (s2 & 0x3) << 12
    off4_field = (off4 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | s2_field | off4_field

    return opcode

"""
This function takes two arguments:

* op1: The 8-bit opcode.
* s2: The 2-bit shift amount.
* s1d: The 4-bit shift amount or displacement.

The function returns the opcode for the SRR format.
"""

def op_from_SRR_format(op1, s2, s1d):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s2_field is the 12th to 13th bits of the opcode.
    The s1d_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    s2_field = (s2 & 0x3) << 12
    s1d_field = (s1d & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | s2_field | s1d_field

    return opcode

"""
This function takes three arguments:

* op1: The 8-bit opcode.
* s2: The 2-bit shift amount.
* s1d: The 4-bit shift amount or displacement.
* n: The 2-bit shift count.

The function returns the opcode for the SRRS format.
"""

def op_from_SRRS_format(op1, s2, s1d, n):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s2_field is the 12th to 13th bits of the opcode.
    The s1d_field is the 8th to 11th bits of the opcode.
    The n_field is the 6th to 7th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    s2_field = (s2 & 0x3) << 12
    s1d_field = (s1d & 0xF) << 8
    n_field = (n & 0x3) << 6

    # Combine the fields to form the opcode
    opcode = op1_field | s2_field | s1d_field | n_field

    return opcode

"""
This function takes two arguments:

* op1: The 8-bit opcode.
* s2: The 2-bit shift amount.
* s1: The 4-bit shift amount or displacement.

The function returns the opcode for the SSR format.
"""

def op_from_SSR_format(op1, s2, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The s2_field is the 12th to 13th bits of the opcode.
    The s1_field is the 8th to 11th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    s2_field = (s2 & 0x3) << 12
    s1_field = (s1 & 0xF) << 8

    # Combine the fields to form the opcode
    opcode = op1_field | s2_field | s1_field

    return opcode

"""
This function takes two arguments:

* op1: The 8-bit opcode.
* off4: The 4-bit offset.
* s1: The 4-bit shift amount or displacement.

The function returns the opcode for the SSRO format.
"""

def op_from_SSRO_format(op1, off4, s1):
    # Extract fields from the opcode
    """
    The op1_field is the first 8 bits of the opcode.
    The off4_field is the 8th to 11th bits of the opcode.
    The s1_field is the 4th to 7th bits of the opcode.
    """
    op1_field = (op1 & 0xFF) << 0
    off4_field = (off4 & 0xF) << 8
    s1_field = (s1 & 0xF) << 4

    # Combine the fields to form the opcode
    opcode = op1_field | off4_field | s1_field

    return opcode

def call(current_ea, target_ea):
    disp24_val = target_ea - current_ea
    disp24_val = (disp24_val >> 1) & 0xFFFFFF
    return op_from_B_format(0x6D, disp24_val)


def ld_b_bol_loam(d_reg_dest,a_reg_source,off16):
    return op_from_BOL_format(0x79, off16, d_reg_dest, a_reg_source)

def ld_a_bol_loam(a_reg_dest,a_reg_source,off16):
    return op_from_BOL_format(0x99, off16, a_reg_dest, a_reg_source)



def ld_hu_bol_loam(d_reg,a_reg,off16):
    return op_from_BOL_format(0xB9, off16, d_reg, a_reg)

def ld_h_bol_loam(d_reg,a_reg,off16):
    return op_from_BOL_format(0xC9, off16, d_reg, a_reg)




def ld_b_bo_soam(d_reg,a_reg,off16):
    return op_from_BO_format(0x09, off16,0x20, d_reg, a_reg)

def ld_bu_bo_soam(d_reg,a_reg,off16):
    return op_from_BO_format(0x09, off16,0x21, d_reg, a_reg)

def ld_h_bo_soam(d_reg,a_reg,off16):
    return op_from_BO_format(0x09, off16,0x22, d_reg, a_reg)

def ld_hu_bo_soam(d_reg,a_reg,off16):
    return op_from_BO_format(0x09, off16,0x23, d_reg, a_reg)

def ld_w_bo_soam(d_reg,a_reg,off16):
    return op_from_BO_format(0x09, off16,0x24, d_reg, a_reg)

def ld_d_bo_soam(d_reg,a_reg,off16):
    return op_from_BO_format(0x09, off16,0x25, d_reg, a_reg)

def ld_a_bo_soam(d_reg,a_reg,off16):
    return op_from_BO_format(0x09, off16,0x26, d_reg, a_reg)

def ld_da_bo_soam(d_reg,a_reg,off16):
    return op_from_BO_format(0x09, off16,0x27, d_reg, a_reg)

def patch_call(ea, call_ea):
    return ida_bytes.patch_bytes(ea,
                                 (call(ea,
                                       call_ea)))








# Test code
if __name__ == "__main__":

    op1 = int(0x6d)
    disp2_value = 0xabcdef

    result = op_from_B_format(op1, disp2_value)
    current_ea = 0x80000412
    target_ea = 0x80001000
    res = call(current_ea, target_ea)

    print((res))

    res = ld_hu_bol(15,15,0x3300)
    if res != 0xb9ff00c3:
        raise ValueError( "Failed test")
