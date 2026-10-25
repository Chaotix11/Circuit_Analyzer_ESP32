# CHAOTIX11

Firmware for ESP 32 processor with WiFi capabilities(ESP32 DevKit1). Designed to work with STM32_Circuit_Analyzer(STM32f411CCU6) and to be processed/displayed by the Raspberry Pi 4b on the GUI- RPI_Circuit_Analyzer

## Temporary Headache Avoidance while still in the works
The project was accidentally nested in another project
the latest cmake is in the 2nd main:
Circuit_Analyzer_ESP32/main/ESP32_circuit_analyzer/main/esp32_boilerplate.c

### DESCRIPTION
This firmware was made while learning how to run shell commands and C coding and while learning what all the layers were. This build is part of an embedded project rabbit hole that I chose as an ET cert capstone. I used AI to teach me, not do it for me. The Capstone was during the final month of my Engineering Tech class @ MiraCosta TCI. The Capstone was to be done while I was nearly failing, still had labs for the current week to do, and had to shadow local hiring firms all while trying to find time to make this work. I was learning niche C, Linux commands, Embedded architecture, while I already determined the problem to solve, hardware, firmware function, and connectivity path and praying I just get to a working proof of concept. I didn't know what a buffer was let alone that these MCUs had all these registers, clock trees, before you even get to all the layers in the main.c. I was just using Arduino IDE before this. I looked the blank boilerplate directly in the face... then I decided to generate up to the main C's. I have a month, not 4 years. The initial problem was to make an embedded device that could show me the overall health of the circuit, then detect and record any parasitic draw from each individual fuse branch on a vehicle. It ended up being more of a forensic-y DAQ than a diagnostic tool when I finally finished the plan. Could be useful for I/O inspection on a PLC while running or a way for a racing team to see what the output is on one specific function while everything is running especially when dealing with sensitive aero activation at a critical moment and failure means tens of thousands of dollars of repair and a DNF.  
 
This MCU, I had the project generated in an ESP IDF 5.5 CMD terminal. That brought me to the point to where I could pull up the CMake in VSCode. I designed some notes about the layer while learning about the layers to keep track of where I was in the build.  

The STM32 project I generated in STM32CubeMX and worked around HAL and wrote on the STM32F411CCU6 in IDE. 

The RPI GUI I edited and ran in Geanie 

