import idautils
import idc
import ida_idp


def find_function_calls(func_find_name, my_func_name):
    """
    Find all function calls to `func_find_name` within the function with the given name.
    """
    # Get the address of the function to search within
    my_func_ea = idc.get_name_ea_simple(my_func_name)
    if my_func_ea == idc.BADADDR:
        raise ValueError(f"Function '{my_func_name}' not found!")
    # Search for calls to the target function
    calls = []
    # Get a list of all instructions in the function
    func_instructions = list(idautils.FuncItems(my_func_ea))
    # TODO we are walking the code but really want to walk the code flow to get all arguments for verification
    for instruction_ea in func_instructions:
        # Check if the current instruction is a call instruction
        if ida_idp.is_call_insn(instruction_ea):
            # Get the target address of the call
            target_ea = idc.get_operand_value(instruction_ea, 0)
            # Get the name of the target function
            target_name = idc.get_name(target_ea)
            if target_name == func_find_name:
                # If the target function's name matches the given name, add the call instruction's address to the list
                calls.append(instruction_ea)
    return calls


if __name__ == "__main__":
    # Example usage: find all calls to function "printf" within function "my_func"
    try:
        printf_calls = find_function_calls("printf", "my_func")
    except ValueError as e:
        print(f"Error: {e}")
    else:
        print("Found", len(printf_calls), "calls to printf within my_func:")
        for call_ea in printf_calls:
            print(hex(call_ea))
