#ifndef GET_CURVE_VALUE_H
#define GET_CURVE_VALUE_H

#include <stdint.h>
#include <stdlib.h>

/**
 * @brief Float axis with a uint8_t size follow by an array of floating points
 *
 */
typedef struct {
  uint8_t x_size;       // Size of the X axis curve
  const float* x_axis;  // Pointer to the X axis curve data
} floataxis_t;

typedef struct {
  uint8_t x_size;  // Size of the X axis of the map
  const floataxis_t* x_axis;
  const float* y_values;  // Pointer to the map data

} curve_xfloatptr_yfloat_t;

float get_curve_value(float x_input, const curve_xfloatptr_yfloat_t* curve);

#endif  // GET_CURVE_VALUE_H