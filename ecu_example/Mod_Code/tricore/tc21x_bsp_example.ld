/******************************************************************************
 * FILE:
 *    tc21x_bsp_example.ld
 *
 * UC ARCHITECTURE:
 *    AURIX TC2x
 *
 * UC FAMILY:
 *    TC21x
 *
 * DESCRIPTION:
 *    TC21x BSP linker file
 *
 * FILE HISTORY:
 *    V1.0    Initial version
 *
 ******************************************************************************
 * Copyright (C) 2015-2021 HighTec EDV-Systeme GmbH.  All rights reserved.
 * This is proprietary software. Any use of the software requires a written
 * license agreement with HighTec EDV-Systeme GmbH. Please contact for
 * detailed license information: info@hightec-rt.com.
 *****************************************************************************/
 

/* ================================================================================================
 * PREDEFINED OUTPUT SECTIONS TO MEMORY REGION ALIASES
 * Aliases allow a quick change in memory placement
 * ==============================================================================================*/

/* CRT0 Boot Code Start */ 
REGION_ALIAS("BOOT", int_flash0)

/* BSP Interrupt handler table in RAM */
REGION_ALIAS("BSP_ISR_HANDLERS_CPU0_", pspr_cpu0) 

/* Core0: Output sections to memory region mapping */
REGION_ALIAS("CODE_CPU0_",      int_flash0)
REGION_ALIAS("RODATA_CPU0_",    int_flash0)
REGION_ALIAS("RAMCODE_CPU0_",   pspr_cpu0)
REGION_ALIAS("DATA_DSPR_CPU0_", dspr_cpu0)

/* Common code and data */
REGION_ALIAS("CODE",     		int_flash0)
REGION_ALIAS("RODATA",   		int_flash0)
REGION_ALIAS("DATA",   			dspr_cpu0)
REGION_ALIAS("RAMCODE",			pspr_cpu0)

/* ================================================================================================
 * PREDEFINED CONSTANTS
 * ==============================================================================================*/

/* Shared Global Stack as defined by AURIX architecture (PSW.IS = 1) 
 * the User stack is left on eventual User or RTOS control (PSW.IS = 0) 
 */
SHARED_STACK_SIZE = 0;     

/* CSA dedicated memory region size defined as 
 * (Number of CSA regions x CSA entry size) where 256 entries is Maximum 
 */
CSA_REGIONS = 0;
CSA_SIZE    = CSA_REGIONS * 64;  

/* General HEAP is case one uses certain stdlib functions */   
__HEAP_SIZE = DEFINED (__HEAP_SIZE) ? __HEAP_SIZE : 0;  



	


/* ================================================================================================
 * SECTIONS: COMMON (shared) sections
 * by default, all example sections are located here
 * ==============================================================================================*/

SECTIONS
{
	/* Code sections */
	.code :	
	{ 
	    *(.text*) 
	} > CODE
	
	/* code to execute from RAM */
	.ramcode :
	{
	    *(.ramcode*)
	} > RAMCODE AT > RODATA
	
	/* read-only data, constants */
	.rodata : 
	{
	    *(.rodata*)
	} > RODATA

	
	/* Short-addressable read-only data */
	.sdata2 : 
	{
	    *(.sdata2*)
	} > RODATA
	
	/* Short-addresable read-write data - initialized */
	.sdata : 
	{
	    *(.sdata*)
	} > DATA AT > RODATA
	
	/* Short-addresable read-write data - non-initialized (zeroed) */
	.sbss : 
	{
	    *(.sbss*)
	} > DATA
	
	/* read-write data - initialized */
	.data : 
	{
	    *(.data*)
	} > DATA AT > RODATA

	/* read-write data - non-initialized */
	.bss : 
	{
	     *(.bss*); 
	     *(COMMON);
	} > DATA
	
	/* HEAP area for stdlib functions */
	.heap : ALIGN(8) 
	{ 
	    . += __HEAP_SIZE;
	} > DATA
}




/* ================================================================================================
 * Linker Symbols
 * ==============================================================================================*/

/* Read only small address pointer */
_SMALL_DATA2_ = ADDR(.sdata2) + 0x8000;

/* Volatile data short address pointer (.sdata before .sbss) */
_SMALL_DATA_ = ADDR(.sdata) + 0x8000;

/* Expected HEAP SYMBOLS */
__HEAP     = ADDR(.heap);
__HEAP_END = SIZEOF(.heap);





/* ================================================================================================
 * DWARF debug sections and others
 * Symbols in the DWARF debugging sections are relative to the
 * beginning of the section, so we begin them at 0.
 * ==============================================================================================*/

SECTIONS
{	
	/* DWARF 1 */
	.comment            0 : { *(.comment) }
	.debug              0 : { *(.debug) }
	.line               0 : { *(.line) }
	
	/* GNU DWARF 1 extensions */
	.debug_srcinfo      0 : { *(.debug_srcinfo) }
	.debug_sfnames      0 : { *(.debug_sfnames) }
	
	/* DWARF 1.1 and DWARF 2 */
	.debug_aranges      0 : { *(.debug_aranges) }
	.debug_pubnames     0 : { *(.debug_pubnames) }
	
	/* DWARF 2 */
	.debug_info         0 : { *(.debug_info) }
	.debug_abbrev       0 : { *(.debug_abbrev) }
	.debug_line         0 : { *(.debug_line) }
	.debug_frame        0 : { *(.debug_frame) }
	.debug_str          0 : { *(.debug_str) }
	.debug_loc          0 : { *(.debug_loc) }
	.debug_macinfo      0 : { *(.debug_macinfo) }
	.debug_ranges       0 : { *(.debug_ranges) }
	
	/* DWARF 2 control flow extension */
	.debug_control_flow 0 : { *(.debug_control_flow) }
	
	/* SGI/MIPS DWARF 2 extensions */
	.debug_weaknames    0 : { *(.debug_weaknames) }
	.debug_funcnames    0 : { *(.debug_funcnames) }
	.debug_typenames    0 : { *(.debug_typenames) }
	.debug_varnames     0 : { *(.debug_varnames) }
	
	.version_info       0 : { *(.version_info) }
}