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
	
	/* read-only data, constants */
	.rodata : 
	{
	    *(.rodata*)
	} > RODATA


	/* read-write data - non-initialized */
	.bss : 
	{
	     *(.bss*); 
	     *(COMMON);
	} > DATA

}