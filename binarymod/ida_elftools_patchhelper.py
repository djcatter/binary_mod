import binascii
import ida_bytes
import idc
import idaapi
import os

from elftools.elf.elffile import ELFFile

def remove_patch_helper(ea, fpos, org_val, patch_val):
    ida_bytes.revert_byte(ea)
    idaapi.del_global_name(ea)
    idaapi.del_local_name(ea)
    # TODO we will need to only do this for areas
    # we wrote ELF data in otherwise it makes a mess
    # i.e. not we we patch a jump for example
    # ida_bytes.del_items(ea)
    return 0


def remove_patch(start_ea, end_ea):
    ida_bytes.visit_patched_bytes(start_ea, end_ea, remove_patch_helper)


def import_elf(filename, code_section_names, data_section_names, ram_section_names = []):
    # Open the ELF file
    with open(filename, 'rb') as file:
        elf = ELFFile(file)

        # Import the CODE sections
        for name in code_section_names:
            code_section = elf.get_section_by_name(name)
            if code_section:
                start_address = code_section['sh_addr']
                #end_address = start_address + code_section['sh_size']
                code_contents = code_section.data()
                ida_bytes.patch_bytes(start_address, code_contents)
            else:
                raise ValueError(f"CODE section '{name}' not found")

        # Import the DATA sections
        for name in data_section_names:
            data_section = elf.get_section_by_name(name)
            if data_section:
                start_address = data_section['sh_addr']
                #end_address = start_address + data_section['sh_size']
                data_contents = data_section.data()
                ida_bytes.patch_bytes(start_address, data_contents)
            else:
                raise ValueError(f"DATA section '{name}' not found")

        # Import symbols
        symbol_tables = elf.get_section_by_name('.symtab')
        if symbol_tables:
            for symbol in symbol_tables.iter_symbols():
                # TODO check to see if we are in the sections that we want.
                symbol_type = symbol.entry.st_info.type
                if symbol_type in ('STT_FUNC', 'STT_OBJECT'):
                    symbol_address = symbol.entry.st_value
                    symbol_name = symbol.name
                    idc.set_name(symbol_address, symbol_name)
                    # TODO import data like functions etc

        else:
            raise ValueError("Symbol table not found in ELF file")
        
# Custom exceptions for better error handling
class PatchedInstructionError(Exception):
    pass

class InstructionMismatchError(Exception):
    pass


def patch_w_check(ea, expected, new_ins):
    # Get the size of the instruction at ea
    insn = idaapi.insn_t()
    ins_size = idaapi.decode_insn(insn,ea)
    if ins_size == 0:
        raise ValueError(f"No instruction found at address {hex(ea)}")

    # Check the length of the expected instruction
    if len(expected) != ins_size:
        raise ValueError("Length of expected instruction doesn't match instruction size")

    # Check the length of the new instruction
    if len(new_ins) != ins_size:
        raise ValueError("Length of new instruction doesn't match instruction size")

    # Load the data at ea based on the instruction length
    data = idaapi.get_bytes(ea, ins_size)

    # Check if the loaded data matches the expected instruction
    if data == expected:
        # Patch the instruction with the new instruction
        ida_bytes.patch_bytes(ea, new_ins)
        return True
    else:
        raise InstructionMismatchError(f"Existing instruction at address {hex(ea)} does not match\n Found {binascii.hexlify(data)} expected {binascii.hexlify(expected)}")



def export_sections_to_file(sections, output_filename):
    with open(output_filename, "wb") as output_file:
        for section in sections:
            address = section["address"]
            length = section["length"]

            # Read the data from the section
            data = idc.get_bytes(address, length)

            # Write the data to the output file
            output_file.write(data)

    print(f"Binary data from sections exported to {output_filename}")