#include "fuelandspark.h"
#include "version_config.h"
const uint8_t version[] = BUILD_VERSION;
volatile float eng_rpm;
volatile float map;
volatile float coolant_temp;
volatile float spark;
volatile float fuel;
volatile uint8_t hello;

int main() {
  while (1) {
    spark = calcSpark(eng_rpm, map, coolant_temp);
    fuel = calcFuel(eng_rpm, map, coolant_temp);
  };
}