/**
 * @file ida_vars.h
 * @brief This is auto generated from the variables of the target disassembly
 * @version 0.1
 * @date 2023-04-18
 * 
 * @copyright Copyright (c) 2023
 * 
 */
#ifndef _DISASEMBLY_VARS_H_
#define _DISASEMBLY_VARS_H_

#include <stdint.h>
#include <stdlib.h>
#include "map_definitions.h"


/* These are from the original binary code */

/**
 *
 * @brief Constant pointer to a floataxis_map_t structure located /
 *  at a memory address.
 *
 *  This macro provides a convenient way to access the floataxis_map_t
 *  structure without having to remember the memory address or cast 
 *  the pointer every time. 
 */
#define rpm_axis (*(const floataxis_map_t*)0X800004B8u)
#define map_axis (*(const floataxis_map_t*)0X800004D0u)


/**
 * @brief This is a function macro to a function already existing 
 * (i.e. outside of our code). The address of the function is at memory 
 * address 0x80000110u.
 * 
 * 
 * #define MACRO_NAME(INPUT1, INPUT2, INPUT3) \ 
 * ((RETURN_TYPE (*)(INPUT1_TYPE, INPUT2_TYPE, INPUT3_TYPE))((ADDRESS))) \
 * (INPUT1, INPUT2, INPUT3)
 * 
 * @param map
 * @param x_input
 * @param y_input
 * @return float
 */

#define get_map_value(x_input, y_input, map) \
    ((float (*)(float, float, const map_xfloat_yfloat_zfloat_t *))((0X80000110u))) \
    (x_input, y_input, map)

/**
 * @brief This is a variable that does not exist in the current code. We
 * are adding a variable in a know good ram location
 * 
 */

#define map_setting  (*(volatile uint8_t*)0X70005014u+1) 

#endif /*_DISASEMBLY_VARS_H_*/