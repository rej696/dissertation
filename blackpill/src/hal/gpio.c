#include "hal/gpio.h"

#include "hal/pinutils.h"
#include "hal/rcc.h"

#include <stdbool.h>
#include <stdint.h>

void gpio_set_mode(uint16_t const pin, uint8_t const mode)
{
    gpio_t *gpio = GPIO(PINBANK(pin));
    uint32_t n = PINNO(pin);
    RCC->AHB1ENR |= BIT(PINBANK(pin));
    gpio->MODER &= ~(0x3U << (n * 2));
    gpio->MODER |= (mode & 0x3U) << (n * 2);
}

bool gpio_set_af(uint16_t const pin, uint8_t const af_num)
{
    gpio_t *gpio = GPIO(PINBANK(pin));
    int n = PINNO(pin);
    gpio->AFR[n >> 3] &= ~(15UL << ((n & 7) * 4));
    gpio->AFR[n >> 3] |= ((uint32_t)af_num) << ((n & 7) * 4);
    return true;
}

void gpio_write(uint16_t const pin, bool const val)
{
    gpio_t *gpio = GPIO(PINBANK(pin));
    if (val) {
        /* Setting using BSRR enables atomic setting of the ODR register, which is
         * the output data register for the gpio */
        /* gpio->ODR |= (1U << PINNO(pin)); */
        gpio->BSRR |= (1U << PINNO(pin));
    } else {
        /* turning off a gpio is done by setting a "reset" bit which is 16 bits
         * further left than the pin number */
        /* gpio->ODR &= ~(1U << PINNO(pin)); */
        gpio->BSRR |= (1U << PINNO(pin) << 16U);
    }
}
