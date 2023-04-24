#include "get_map_value.h"

/**
 * @brief Get the map value object
 *
 * This function first computes the indices of the map elements that surround
 * the input values using a simple linear search. Finally, the function uses
 * bilinear interpolation to compute the interpolated value at the given input
 * location. Note that this function assumes that the input values x_input and
 * y_input are within the range of the corresponding axis curves, so it does not
 * perform any input range checks.
 *
 * @param map
 * @param x_input
 * @param y_input
 * @return float
 */

float get_map_value(float x_input, float y_input,
                    const map_xfloat_yfloat_zfloat_t * map) {
  // Compute the x and y indices
  int x_index = 0, y_index = 0;
  while (x_index < map->x_size - 1 &&
         x_input > map->x_axis->x_axis[x_index + 1]) {
    x_index++;
  }
  while (y_index < map->y_size - 1 &&
         y_input > map->y_axis->x_axis[y_index + 1]) {
    y_index++;
  }
  // Compute the map index
  int map_index = x_index * map->y_size + y_index;
  // Interpolate the value using bilinear interpolation
  float x_frac =
      (x_input - map->x_axis->x_axis[x_index]) /
      (map->x_axis->x_axis[x_index + 1] - map->x_axis->x_axis[x_index]);
  float y_frac =
      (y_input - map->y_axis->x_axis[y_index]) /
      (map->y_axis->x_axis[y_index + 1] - map->y_axis->x_axis[y_index]);
  float z_value1 = map->z_values[map_index];
  float z_value2 = map->z_values[map_index + map->y_size];
  float z_value3 = map->z_values[map_index + 1];
  float z_value4 = map->z_values[map_index + map->y_size + 1];
  return z_value1 * (1 - x_frac) * (1 - y_frac) +
         z_value2 * (1 - x_frac) * y_frac + z_value3 * x_frac * (1 - y_frac) +
         z_value4 * x_frac * y_frac;
}
