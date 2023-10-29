#!/usr/bin/python3

# Copyright (C) 2023 Zoltan Fekete
# Program adjusted to handle PIC 16F1xxx modern enhanced mid-range controllers
# using in conjunction with author's bootloader code for PIC16F1xxx series controllers.
#
# This program is fundamentally based on an1310.py written by:
# Copyright (C) 2019  Michele Alessandrini  [https://github.com/MAlessandrini-Univpm/an1310-python]

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3
# as published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import platform # built-in module
import time
import serial
import serial.tools.list_ports


ser = serial.Serial(port='/dev/ttyAMA0', baudrate = 9600, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, timeout=1)
for a in range(0,1000):
	print(a)
	ser.write(b'a')
	ser.flush()
