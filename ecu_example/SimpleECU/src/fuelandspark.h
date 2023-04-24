#ifndef FUEL_AND_SPARK_H
#define FUEL_AND_SPARK_H

#include <stdio.h>
#include "../characteristicshandler/get_curve_value.h"
#include "../characteristicshandler/get_map_value.h"



float calcSpark(float eng_rpm, float map, float coolant_temp);

float calcFuel(float eng_rpm, float map, float coolant_temp);

#endif // FUEL_AND_SPARK_HF