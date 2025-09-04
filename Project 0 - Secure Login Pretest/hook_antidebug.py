import sys
import platform

# Detect debugger
if sys.gettrace(): # Gets the trace of the program, if "not None" quit
    sys.exit("Debugger detected. Exiting...")

# Detect VM
vm_indicators = ['virtual', 'vmware', 'vbox', 'qemu']
platform_data = platform.platform().lower() # Use Pythons built-in os detail printer, if it has any signs of VM potential, exit

if any(indicator in platform_data for indicator in vm_indicators):
    sys.exit("Virtual machine detected. Exiting...")
