#ifndef _RGB_LED_H
#define _RGB_LED_H

#include <NeoPixelBus.h>

/// Available LED colors
typedef enum {RED, GREEN, BLUE, YELLOW, PURPLE, CYAN, WHITE, BLACK} RGB_LED_COLOR;

/**
 * Function that sets up LED
 * @return No return value
 */
void RGB_LED_init(void);

/**
 * Function that sets color saturation for LED
 * @param saturation - Color saturation
 * @return No return value
 */
void RGB_LED_setSaturation(uint8_t saturation);

/**
 * Function that sets color of LED
 * @param color - Color of the LED
 * @return No return value
 */
void RGB_LED_setColor(RGB_LED_COLOR color);

#endif
