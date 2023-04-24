from elftools.elf.elffile import ELFFile
import ida_bytes
import idc
import idaapi


def remove_patch_helper(ea, fpos, org_val, patch_val):
    ida_bytes.revert_byte(ea)
    idaapi.del_named_item(ea)
    return 0;


def remove_patch(start_ea, end_ea):
    ida_bytes.visit_patched_bytes(start_ea, end_ea, remove_patch_helper)




def import_elf(filename, code_section_names, data_section_names):
    # Open the ELF file
    with open(filename, 'rb') as f:
        elf = ELFFile(f)

        # Import the CODE sections
        for name in code_section_names:
            code_section = elf.get_section_by_name(name)
            if code_section:
                start_address = code_section['sh_addr']
                end_address = start_address + code_section['sh_size']
                code_contents = code_section.data()
                ida_bytes.patch_bytes(start_address, code_contents)
            else:
                raise ValueError(f"CODE section '{name}' not found")

        # Import the DATA sections
        for name in data_section_names:
            data_section = elf.get_section_by_name(name)
            if data_section:
                start_address = data_section['sh_addr']
                end_address = start_address + data_section['sh_size']
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
            raise ValueError(f"Symbol table not found in ELF file")
