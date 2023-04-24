/******************************************************************************
 * FILE:
 *    tc21x_simple_ecu.ld
 *
 * DESCRIPTION:
 *    TC21x BSP linker file
 *
 * FILE HISTORY:
 *    V1.0    Initial version
 *
 *****************************************************************************/
 

/* ================================================================================================
 * PREDEFINED OUTPUT SECTIONS TO MEMORY REGION ALIASES
 * Aliases allow a quick change in memory placement
 * ==============================================================================================*/

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


/* General HEAP is case one uses certain stdlib functions */   
__HEAP_SIZE = DEFINED (__HEAP_SIZE) ? __HEAP_SIZE : 4K;  




	


/* ================================================================================================
 * SECTIONS: Cores' Shared Stacks 
 * Each core has its own Shared stack area (PSW.IS = 1)
 * ==============================================================================================*/

SECTIONS
{
	.CPU0.stack : { . = ALIGN(8); __STACK_BASE_CPU0_ = .; . += SHARED_STACK_SIZE; } > RAMCODE 
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


