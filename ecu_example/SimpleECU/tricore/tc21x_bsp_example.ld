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
SHARED_STACK_SIZE = 4K;     

/* CSA dedicated memory region size defined as 
 * (Number of CSA regions x CSA entry size) where 256 entries is Maximum 
 */
CSA_REGIONS = 256;
CSA_SIZE    = CSA_REGIONS * 64;  

/* General HEAP is case one uses certain stdlib functions */   
__HEAP_SIZE = DEFINED (__HEAP_SIZE) ? __HEAP_SIZE : 4K;  


/* ================================================================================================
 * SECTIONS: BMHD headers
 * ==============================================================================================*/
 
SECTIONS
{
	/* Boot Mode Headers (BMHD) - place only BMHD_0 */
	.bmhd_0_org : { KEEP (*(.bmhd)) } > bmhd_0
}


/* ================================================================================================
 * Application BOOT code
 * Address pointed by BMHD start address value
 * ==============================================================================================*/

SECTIONS
{
	.crt0_boot 0x80000020 : { KEEP (*(.crt0_boot.code)) } > BOOT  
}

	


/* ================================================================================================
 * SECTIONS: Reset Default TRAP handlers provided by BSP 
 * the TRAP table is shared across cores
 * BTV register value after reset is 0xA0000100 (0x80000100)
 * ==============================================================================================*/

SECTIONS
{
	.bsp_trap_reset 0x80000100 :
	{
		KEEP (*(.bsp_trap_vector_table))
		KEEP (*(.bsp_trap_handlers))
	} > CODE_CPU0_
}
	
	
/* ================================================================================================
 * SECTIONS: BSP Interrupt tables
 * BSP provided Interrupt vector table
 * ==============================================================================================*/

SECTIONS
{
	.CPU0.bsp_isr_vector_table : { KEEP (*(.bsp_isr_vector_table_cpu0)) } > CODE_CPU0_
}

SECTIONS
{
    .CPU0.bsp_isr_ram_table (NOLOAD) : { *(.BspIsrRamTable_Cpu0) } > BSP_ISR_HANDLERS_CPU0_ 

}

/* ================================================================================================
 * SECTIONS: Cores' CSA regions 
 * Each core has its own CSA region list
 * ==============================================================================================*/

SECTIONS
{
	.CPU0.csa (NOLOAD) : { . = ALIGN(64); __CSA_BASE_CPU0_ = .; . +=  CSA_SIZE; } > DATA_DSPR_CPU0_
}


/* ================================================================================================
 * SECTIONS: Cores' Shared Stacks 
 * Each core has its own Shared stack area (PSW.IS = 1)
 * ==============================================================================================*/

SECTIONS
{
	.CPU0.stack : { . = ALIGN(8); __STACK_BASE_CPU0_ = .; . += SHARED_STACK_SIZE; } > DATA_DSPR_CPU0_ 
}


/* ================================================================================================
 * SECTIONS: CORE 0 dedicated sections
 * In the example they are Empty, but user might used them to play
 * with core specific placement
 * ==============================================================================================*/

SECTIONS
{
	.CPU0.code     : {  } > CODE_CPU0_
	.CPU0.ramcode  : {  } > RAMCODE_CPU0_ AT > RODATA_CPU0_
	.CPU0.rodata   : {  } > RODATA_CPU0_
	.CPU0.data     : {  } > DATA_DSPR_CPU0_ AT > RODATA_CPU0_
	.CPU0.bss      : {  } > DATA_DSPR_CPU0_
}


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
			FILL(0xDEADBEEF);
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
 * SECTIONS: CLEAR & COPY TABLES with END delimiter to support crt0 init
 * clear_table: 
 *    data memory ranges to clear to zero
 * copy_table:  
 *    data memory ranges that needs to be value initialized
 *    (init values are stored in FLASH and copied to RAM)
 * Each core has its own table to process during its init to allow multicore execution. 
 * Shared resources are inserted to Core[0] tables (the RESET core)
 * ==============================================================================================*/
SECTIONS
{
    /*-------------------------------------------------------------------------------------------*/

	.CPU0.clear_sec :
	{
		LONG(ADDR(.CPU0.bss)); LONG(SIZEOF(.CPU0.bss));
		LONG(ADDR(.sbss)); LONG(SIZEOF(.sbss)); 
		LONG(ADDR(.bss)); LONG(SIZEOF(.bss));
		LONG(ADDR(.heap)); LONG(SIZEOF(.heap));
		LONG(-1); LONG(-1);
	} > RODATA_CPU0_

	.CPU0.copy_sec :
	{
		LONG(LOADADDR(.CPU0.ramcode)); LONG(ADDR(.CPU0.ramcode)); LONG(SIZEOF(.CPU0.ramcode));
		LONG(LOADADDR(.CPU0.data)); LONG(ADDR(.CPU0.data)); LONG(SIZEOF(.CPU0.data));
		LONG(LOADADDR(.ramcode)); LONG(ADDR(.ramcode)); LONG(SIZEOF(.ramcode));
		LONG(LOADADDR(.sdata)); LONG(ADDR(.sdata)); LONG(SIZEOF(.sdata));
		LONG(LOADADDR(.data)); LONG(ADDR(.data)); LONG(SIZEOF(.data));
		LONG(-1); LONG(-1); LONG(-1);
	} > RODATA_CPU0_

	/*-------------------------------------------------------------------------------------------*/
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
 * CRT0 CONFIG STRUCTURE
 * Initialization structure for uC Cores used in crt0 startup code
 * Each core has itw one table entry.
 * ==============================================================================================*/

SECTIONS
{
	.crt0_config : ALIGN(4)
	{
		PROVIDE(__crt0_config = .);        /* base of the crt0 config table */
		
		/* Core[0] */
		LONG(ADDR(.CPU0.stack));           /* STACK address */ 
		LONG(SIZEOF(.CPU0.stack));         /* STACK size */
		LONG(ADDR(.CPU0.csa));             /* CSA address */ 
		LONG(SIZEOF(.CPU0.csa));           /* CSA size */
		LONG(_SMALL_DATA_);                /* SDATA address */
		LONG(_SMALL_DATA2_);               /* SDATA2 address */
		LONG(0);                           /* SDATA3 address */
		LONG(0);                           /* SDATA4 address */
		LONG(ADDR(.CPU0.clear_sec));       /* CLEAR table */
		LONG(ADDR(.CPU0.copy_sec));        /* COPY table */
		

	} > RODATA 

	.fill :
	{
					_FillStartAddress = .; /* Provides start address of Filled location */
					KEEP(*(.fill_known_data))
					FILL(0xFF);
					. = 0x20000; /* TODO FIX ME ORIGIN(int_flash0) + LENGTH(int_flash0) - _FillStartAddress; /* Fill till end of rom */
					_FillEndAddress = .; /* Provides end address of Filled location */
	}  > RODATA
}


/* ================================================================================================
 * DWARF debug sections and others
 * Symbols in the DWARF debugging sections are relative to the
 * beginning of the section, so we begin them at 0.
 * ==============================================================================================*/

SECTIONS
{	
	/* DWARF 1 */
	.commsent            0 : { *(.comment) }
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