import re
import idaapi


def get_address_from_name(name):
    """Returns the hex address of the given name in IDA"""
    ea = idaapi.get_name_ea(0, name)
    if ea == idaapi.BADADDR:
        return None
    return hex(ea).upper()


class LabelNotFoundException(Exception):
    pass

class UnknownOperatorException(Exception):
    pass

# Define a regular expression pattern for matching $IDA_ADDR(Name), $IDA_ADDR(Name+N), and $IDA_ADDR(Name-N)
pattern = r'\$IDA_ADDR\((\w+)([+-]\d+)?\)'


def ida_address_findreplace(input_filename, output_filename):
    # Open the input file for reading
    with open(input_filename, 'r') as infile:

        # Open the output file for writing
        with open(output_filename, 'w') as outfile:

            # Loop over each line in the input file
            for line in infile:

                # Use regular expression search to find all instances of $IDA_ADDR(Name)
                matches = re.findall(pattern, line)

                # Loop over each match and replace it with the corresponding hex address from IDA
                for name,offset in matches:
                    hex_addr = get_address_from_name(name)
                    if(hex_addr is None):
                        raise LabelNotFoundException("Label '{}' not found".format(name))
                    # If there is an offset, add it to the hex address
                    if offset:
                        operator = offset[0]  # Get the operator (+ or -)
                        value = int(offset[1:])  # Get the numerical value
                        # print("Label '{}' found".format(name))
                        # print("Offset '{}'".format(value))
                        # print("Operator '{}'".format(operator))
                        if operator == '+':
                            hex_addr = hex(int(hex_addr, 16) + value)
                        elif operator == '-':
                            hex_addr = hex(int(hex_addr, 16) - value)
                        else:
                            raise UnknownOperatorException("Operator found when looking for '{}' not found".format(name))         
                        line = line.replace(f'$IDA_ADDR({name}{operator}{value})', hex_addr)
                    else:                 
                        line = line.replace(f'$IDA_ADDR({name})', hex_addr)

                # Write the modified line to the output file
                outfile.write(line)
