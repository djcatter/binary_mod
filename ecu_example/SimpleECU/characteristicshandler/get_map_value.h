#ifndef GET_MAP_VALUE_H
#define GET_MAP_VALUE_H

#include <stdint.h>
#include <stdlib.h>

/**
 * @brief Float axis with a uint8_t size follow by an array of floating points
 *
 */
typedef struct {
  uint8_t x_size;       // Size of the X axis curve
  const float* x_axis;  // Pointer to the X axis curve data
} floataxis_map_t;

typedef struct {
  uint8_t x_size;  // Size of the X axis of the map
  uint8_t y_size;  // Size of the Y axis of the map
  const floataxis_map_t* x_axis;
  const floataxis_map_t* y_axis;
  const float* z_values;  // Pointer to the map data

} map_xfloat_yfloat_zfloat_t;

float get_map_value(float x_input, float y_input,
                    const map_xfloat_yfloat_zfloat_t* map);

#endif  // GET_MAP_VALUE_H