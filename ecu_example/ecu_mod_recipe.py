import os
import shutil
import subprocess


# Import the required IDAPython modules
import ida_idaapi
import ida_kernwin
import idc
import ida_name

import ida_elftools_patchhelper
import ida_infineon_helper 
import ida_relabel 
import ida_find_function_calls

from datetime import datetime




def ecu_mod_recipe():
  # First we will try to get the dependancies from the mod code to compile
  # assumptions is that the idb is complete and labeled correctly
  startTime = datetime.now()
  print("====================ECU mode recipe demo====================")

  print("Clearing out old patch data to allow for this to be used for development.")
  ida_elftools_patchhelper.remove_patch(0,idc.BADADDR)

  print("Getting the data from IDA that we need to compile code.")
  # Define the paths to the files to modify
  input_file = "Mod_Code/src/disasembly_vars.h_in" # This is the template file
  output_file = "Mod_Code/src/disasembly_vars.h"   # This is the output file

  # Find and replace the target string in the input file
  ida_relabel.ida_address_findreplace(input_file, output_file)


  print("Clear CMake build folder to compile code clean.")

  # Change the current working directory to the Mod_Code directory
  os.chdir("Mod_Code") # TODO need to CD back if we fail after this step

  # Clean the build directory to make sure we are getting fresh results
  shutil.rmtree("build")
  os.makedirs("build")



      

  # TODO add a environment check to make sure we have a compiler set to make this generic
  # TODO clean up pathing

  # Build the project using CMake

  print("======Running CMake to get environment variables setup to build.======")

  cmake_process = subprocess.Popen(["cmake", "-D", "CMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE",
                                    "-D", "CMAKE_C_COMPILER=tricore-gcc.exe",
                                    "-S", ".",
                                    "-B", "./build",
                                      "-G", "Unix Makefiles"],  
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.STDOUT)
  for line in cmake_process.stdout:
      ida_kernwin.msg(line.decode())
  cmake_process.wait()


  print("======Running CMake build======")

  build_process = subprocess.Popen(["cmake", "--build", "."], cwd="build", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  for line in build_process.stdout:
      ida_kernwin.msg(line.decode())
  build_process.wait()

  os.chdir("..") 


  print("======Importing Elf File and Names======")
  # Import the elf file and segment names
  elf_file = "Mod_Code/build/mod_code.elf"
  code_segments = [".code"]
  rodata_segments = [".rodata"]

  ida_elftools_patchhelper.import_elf(elf_file, code_segments, rodata_segments)

  print("======Finding where to patch and patching======")
  get_map_value_calls = ida_find_function_calls.find_function_calls("get_map_value", "calcFuel")

  # Always check to make sure you are patching correctly
  if(len(get_map_value_calls)!= 1):
      raise ValueError(f"Recipe is only setup for modify calcFuel with one call to get_map_value!")
      

  # Get the address of the function named "fuel_curve_overload" our function we are overloading
  overload_func_ea = ida_name.get_name_ea(0, "fuel_curve_overload")
  # Check if the function was not found
  if overload_func_ea == ida_idaapi.BADADDR:
    raise ValueError(f"Recipe error! We could not find the function to patch to!")    
  ida_infineon_helper.patch_call(get_map_value_calls[0],overload_func_ea )
  print('======Done in ',(datetime.now() - startTime),  'seconds======')

    