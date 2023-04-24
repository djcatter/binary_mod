#include "disasembly_vars.h"
#include "map_definitions.h"




const static float mod1_fuel_curve[] = {0.0, 0.0, 0.0, 0.0, 0.7, 1.2, 1.7, 2.2,
                                   1.2, 2.2, 3.2, 4.2, 1.7, 3.2, 4.7, 6.2};

const static map_xfloat_yfloat_zfloat_t mod1_fuel_map = {.x_size = 4,
                                                    .y_size = 4,
                                                    .x_axis = &rpm_axis,
                                                    .y_axis = &map_axis,
                                                    .z_values = mod1_fuel_curve};







float fuel_curve_overload(float x_input, float y_input, map_xfloat_yfloat_zfloat_t * stock_fuel_curve) {
  if (map_setting > 0)
  {
    return get_map_value(x_input, y_input, &mod1_fuel_map);
  }
  else{    
    return get_map_value(x_input, y_input, stock_fuel_curve);
  };
}