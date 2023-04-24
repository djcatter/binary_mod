#ifndef _MAP_DEFINITIONS_H_
#define _MAP_DEFINITIONS_H_
#include <stdint.h>

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


#endif /* _MAP_DEFINITIONS_H_ */