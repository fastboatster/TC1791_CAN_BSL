# Simos 8.4/8.5 Raspberry Pi connections for SBOOT Shell Exploit Seed Response Testing
## Simos 8.4 connections to Raspberry Pi:
Only used to test if the seed is returned, no attempt to extract the passwords.
- Connector with 94 contacts:
- 68 CAN Hi
- 67 CAN Lo
- 64 +12V
- 87 +12V
- 2 - ground from the power supply
- 1 - ground from Raspberry Pi (pin 34, although any ground should work. pin 34
 is also used as level converter's ground)
- Connector with 60 contacts:
- 25 - pin 32 Raspberry Pi (GPIO 12 (PWM0))
- 11 - pin 33 Raspberry Pi (GPIO 13 (PWM1))
 Note: all Raspberry Pi pin numbers are from pinout.xyz

![Raspberry Pi Simos 8.4 SBOOT Shell Seed response](simos8.4_sboot_shell_seed_response.png)

## Simos 8.5 connections to Raspberry Pi:
Nearly identical to 8.4 except for PWM pins:
- Connector with 94 contacts:
 - 68 CAN Hi
 - 67 CAN Lo
 - 64 +12V
 - 87 +12V
 - 2 - ground from the power supply
 - 1 - ground from Raspberry Pi (pin 34, although any ground should work. pin 34
 is also used as level converter's ground)
- Connector with 60 contacts:
 - 55 - pin 32 Raspberry Pi (GPIO 12 (PWM0))
 - 40 - pin 33 Raspberry Pi (GPIO 13 (PWM1))

![Raspberry Pi Simos 8.5 SBOOT Shell Seed response](simos8.5_sboot_shell_seed_response.png)
 Example Simos 8.5 256 byte seed:
 ```
 5dfa941482de0bf5370158c067f08f6e45d7887870d078255f0557d3751f3da23b8f1059a4bfe8b885b5f856084850fea65711e6e58b795b28bd0be0d36be9ae69a04da68431669e80d4e442de1be7b1446151995c8a27cb63c5ae05f804bb869effb282581b0d15e1212e9632e9b3c272a8a53c85cf85f6be0332d33735beb6
 ```

 Obtained using `test_pwm` command in `bootloader.py` by quickly hitting `Enter` when prompted to turn on the ECU power and then turning the ECU power very quickly after that.
