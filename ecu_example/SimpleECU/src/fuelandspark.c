#include <stdio.h>

#include "../characteristicshandler/get_curve_value.h"
#include "../characteristicshandler/get_map_value.h"

// Define the range of the X axis (engine RPM) and the corresponding values
const static float rpm_axis_values[4] = {1000.0f, 2000.0f, 3000.0f, 4000.0f};
const static floataxis_map_t rpm_axis = {4, rpm_axis_values};

// Define the range of the Y axis (MAP psi) and the corresponding values
const static float map_axis_values[4] = {1.0f, 2.0f, 3.0f, 4.0f};
const static floataxis_map_t map_axis = {4, map_axis_values};

// Define the values of ignition timing for each point in the map
const static float ignition_timing[16] = {
    10.0f, 11.0f, 12.0f, 13.0f, 14.0f, 15.0f, 16.0f, 17.0f,
    18.0f, 19.0f, 20.0f, 21.0f, 22.0f, 23.0f, 24.0f, 25.0f};

// Create the map using the defined X and Y axis and ignition timing values
const static map_xfloat_yfloat_zfloat_t ignition_map = {
    4, 4, &rpm_axis, &map_axis, ignition_timing};

// Global curve data
const static float spark_curve_x[] = {0.0, 1.0, 2.0, 3.0};
const static float spark_curve_y[] = {0.0, 5.0, 10.0, 15.0};
const static float fuel_curve_x[] = {0.0, 1.0, 2.0, 3.0};
const static float fuel_coolant_y_axis[] = {0.0, 2.5, 5.0, 7.5};

// Global map data

const static float coolant_axis_values[4] = {-20.0f, 0.0f, 100.0f, 200.0f};
const static floataxis_t coolant_axis = {4, coolant_axis_values};

const static float fuel_map_z[] = {0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 1.5, 2.0,
                                   1.0, 2.0, 3.0, 4.0, 1.5, 3.0, 4.5, 6.0};
/**
 * @brief Map structure for the main fuel
 * 
 */
const static map_xfloat_yfloat_zfloat_t fuel_map = {.x_size = 4,
                                                    .y_size = 4,
                                                    .x_axis = &rpm_axis,
                                                    .y_axis = &map_axis,
                                                    .z_values = fuel_map_z};
/**
 * @brief Curve structure for spark coolant compensation
 * 
 */
const static curve_xfloatptr_yfloat_t spark_colant_temp = {
    .x_size = 4, .x_axis = &coolant_axis, .y_values = spark_curve_y};

/**
 * @brief Curve structure for fuel coolant compensation
 * 
 */
const static curve_xfloatptr_yfloat_t fuel_coolant_temp = {
    .x_size = 4, .x_axis = &coolant_axis, .y_values = fuel_coolant_y_axis};
/**
 * @brief calcSpark an elementary function that calculates a fake spark
 * based on a curve and a map.
 * 
 * @param eng_rpm float of engine rpm
 * @param map float of map pressure
 * @param coolant_temp float of coolant temp
 * @return float 
 */
float calcSpark(float eng_rpm, float map, float coolant_temp) {
  float spark_coolant_result =
      get_curve_value(coolant_temp, &spark_colant_temp);

  float spark_map_result = get_map_value(eng_rpm, map, &ignition_map);

  return spark_coolant_result + spark_map_result;
}

/**
 * @brief calcFuel is a straightforward function that calculates a fake fuel
 * based on a curve and a map.
 * 
 * @param eng_rpm float of engine rpm
 * @param map float of map pressure
 * @param coolant_temp float of coolant temp
 * @return float 
 */
float calcFuel(float eng_rpm, float map, float coolant_temp) {
  float fuel_coolant_result = get_curve_value(coolant_temp, &fuel_coolant_temp);

  float fuel_map_result = get_map_value(eng_rpm, map, &fuel_map);

  return fuel_coolant_result + fuel_map_result;
}
