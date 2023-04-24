#include "get_curve_value.h"

/**
 * @brief Get the curve value object
 * This implementation still computes the index of the curve element that
 * surrounds x_input using a while loop. However, it does not check if x_input
 * is within the range of the curve. If x_input is outside the range of the
 * curve, the function will still try to interpolate a value using the closest
 * available curve elements. Note that this implementation could produce
 * unexpected results if the input value is far outside of the curve range.
 *
 * @param x_input
 * @param curve
 * @return float
 */
float get_curve_value(float x_input, const curve_xfloatptr_yfloat_t* curve) {
  // Compute the index of the curve element that surrounds x_input
  int index = 0;
  while (index < curve->x_size - 1 &&
         x_input > curve->x_axis->x_axis[index + 1]) {
    index++;
  }
  // Interpolate the curve value using linear interpolation
  float x_frac =
      (x_input - curve->x_axis->x_axis[index]) /
      (curve->x_axis->x_axis[index + 1] - curve->x_axis->x_axis[index]);
  float y_value1 = curve->y_values[index];
  float y_value2 = curve->y_values[index + 1];
  return y_value1 * (1 - x_frac) + y_value2 * x_frac;
}
