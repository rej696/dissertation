#ifndef GPIO_H_
#define GPIO_H_

#include <stdint.h>
#include <stdbool.h>
#include "rcc.h"
#include "pinutils.h"

typedef struct gpio {
    volatile uint32_t MODER;
    volatile uint32_t OTYPER;
    volatile uint32_t OSPEEDR;
    volatile uint32_t PUPDR;
    volatile uint32_t IDR;
    volatile uint32_t ODR;
    volatile uint32_t BSRR;
    volatile uint32_t LCKR;
    volatile uint32_t AFR[2];
} gpio_t;

#define GPIO(bank) ((gpio_t *) (0x40020000 + 0x400 * (bank)))

typedef enum {
    GPIO_MODE_INPUT = 0,
    GPIO_MODE_OUTPUT = 1,
    GPIO_MODE_AF = 2,
    GPIO_MODE_ANALOG = 3
} gpio_mode_t;

void gpio_set_mode(uint16_t const pin, uint8_t const mode);
bool gpio_set_af(uint16_t const pin, uint8_t const af_num);
void gpio_write(uint16_t const pin, bool const val);

#endif /* GPIO_H_ */
