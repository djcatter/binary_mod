/**************************************************************************************************
 * FILE: tc21x_memory.ld
 *
 * UC ARCHITECTURE:
 *
 *    TC2xx
 *
 * UC FAMILY:
 *
 *    TC21x
 *
 * DESCRIPTION:
 *
 *    uC family memory region definition file.
 *    Not all available memory regions are defined, only those used in BSP example.
 *    It includes the application linker files locating sections to memory regions at the end.
 *
 * FILE HISTORY:
 *
 *    V1  03.2019  
 *    - Update to PXROS-HR v7.3.0.
 *
 *    V2  03.2021  JS
 *    - Update to PXROS-HR v8.2.0
 *
 **************************************************************************************************
 * Copyright (C) 2015-2021 HighTec EDV-Systeme GmbH.  All rights reserved.
 * This is proprietary software. Any use of the software requires a written
 * license agreement with HighTec EDV-Systeme GmbH. Please contact for
 * detailed license information: info@hightec-rt.com.
 *************************************************************************************************/
 
OUTPUT_FORMAT("elf32-tricore")
OUTPUT_ARCH(tricore)
ENTRY(_crt0_reset)

/* ================================================================================================
 * TC2XX MEMORY REGIONS
 * ==============================================================================================*/

MEMORY
{
  /* Program Flash memory - cached region */
  int_flash0 (rx):      org = 0x80001000, len = 20K

  /* Program scratchpad memories */
  pspr_cpu0 (rx):       org = 0x70100000, len = 8K

  /* Data scratchpad memories */
  dspr_cpu0 (w!x):      org = 0x70000000, len = 48K
  
  /* Periphery memory space region */
  periphery_base :      org = 0xF0000000, len = 0
  periphery_end  :      org = 0xFFFF0000, len = 0
  
  /* BMHDs (Boot Mode Headers) located in PFLASH */
  bmhd_0 (rx) : 		org = 0xa0000000, len = 32
  bmhd_1 (rx) : 		org = 0xa0020000, len = 32
  bmhd_2 (rx) : 		org = 0xa000ffe0, len = 32
  bmhd_3 (rx) : 		org = 0xa001ffe0, len = 32
}

/* ================================================================================================
 * MEMORY REGION SYMBOLS
 * ==============================================================================================*/

/* Internal Flash memory */
INT_FLASH_MEMORY_BASE = ORIGIN(int_flash0);
INT_FLASH_MEMORY_SIZE = 512K;

/* ================================================================================================
 * INCLUDE OF APPLICATION LINKER FILE
 * ==============================================================================================*/
 
/*INCLUDE tc21x_bsp_example.ld*/
