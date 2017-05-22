from immlib import *

def main(args):

    imm = Debugger()
    
    bad_char_found = False

    address = int(args[0],16)

    try:
        file = open("C:/Users/mizushimashunto/hacker/Debugger/download_exec.bin", "r")
        shellcode = file.read()
        shellcode_length = len(shellcode)
        file.close()

        debug_shellcode = imm.readMemory(address,shellcode_length)

        imm.log("Address: 0x%08x" % address)
        imm.log("Shellcode Length : %d" % shellcode_length)

        imm.log("Attack Shellcode: %s" % shellcode.encode("HEX"))
        imm.log("In Memory Shellcode: %s" % debug_shellcode("HEX"))

        count = 0
        while count < shellcode_length:

            if debug_shellcode[count] != shellcode[count]:

                imm.log("Bad Char Detected at offset %d" % count)
                bad_char_found = True
                break
            
            count+=1

        if bad_char_found:
            imm.log("[*****]")
            imm.log("Bad character found: %s" % debug_shellcode[count].encode("HEX"))
            imm.log("Bad character original: %s" % shellcode[count].encode("HEX"))
            imm.log("[*****]")



    except:
        print "File open error."



    
        
    return "[*] !badchar finished, check Log window."
        

    
