import sys
import platform

# Detect debugger
if sys.gettrace():
    sys.exit("Debugger detected. Exiting...")

# Detect VM
vm_indicators = ['virtual', 'vmware', 'vbox', 'qemu']
platform_data = platform.platform().lower()

if any(indicator in platform_data for indicator in vm_indicators):
    sys.exit("Virtual machine detected. Exiting...")
