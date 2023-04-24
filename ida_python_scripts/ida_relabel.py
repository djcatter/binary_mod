import re
import idaapi

def get_address_from_name(name):
    """Returns the hex address of the given name in IDA"""
    ea = idaapi.get_name_ea(0, name)
    if ea == idaapi.BADADDR:
        return None
    return hex(ea).upper()


# Define a regular expression pattern for matching $IDA_ADDR(Name)
pattern = r'\$IDA_ADDR\((\w+)\)'

def ida_address_findreplace (input_filename, output_filename):
  # Open the input file for reading
  with open(input_filename, 'r') as infile:

      # Open the output file for writing
      with open(output_filename, 'w') as outfile:
          
          # Loop over each line in the input file
          for line in infile:
              
              # Use regular expression search to find all instances of $IDA_ADDR(Name)
              matches = re.findall(pattern, line)
              
              # Loop over each match and replace it with the corresponding hex address from IDA
              for name in matches:
                  hex_addr = get_address_from_name(name)
                  line = line.replace(f'$IDA_ADDR({name})', hex_addr)
                  
              # Write the modified line to the output file
              outfile.write(line)