#ifndef PINUTILS_H_
#define PINUTILS_H_

#define BIT(x) (1UL << (x))
#define PIN(bank, num) ((((bank) - 'A') << 8) | (num))
#define PINNO(pin) (pin & 0xFF)
#define PINBANK(pin) (pin >> 8)

#endif /* PINUTILS_H_ */
