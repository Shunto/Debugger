from pydbg import *
from pydbg.defines import *

import utils

MAX_INSTRUCTIONS = 10

dangerous_functions = {
                        "strcpy"   : "msvcrt.dll",
                        "strncpy"  : "msvcrt.dll",
                        "sprintf"  : "msvcrt.dll",
                        "vsprintf" : "msvcrt.dll"
                      }

dangerous_functions_resolved = {}
crash_encoutered             = False
instruction_count            = 0

def danger_handler(dbg):
    
    esp_offset = 0
    print "[*] Hit %s" % dangerous_functions_resolved[dbg.context.Eip]
    print "============================================================"

    while esp_offset <= 20:
        parameter = dbg.smart_dereference(dbg.context.Esp + esp_offset)
        print "[ESP + %d] => %s" % (esp_offset, parameter)
        esp_offset += 4

    print "============================================================\n"

    dbg.suspend_all_threads()
    dbg.process_snapshot()
    dbg.resume_all_threads()

    return DBG_CONTINUE

def access_violation_handler(dbg):
    global crash_encountered

    if dbg.dbg.u.Exception.dwFirstChance:
        return DBG_EXCEPTION_NOT_HANDLED

    crash_bin = utils.crash_binning.crash_binning()
    crash_bin.record_crash(dbg)
    print crash_bin.crash_synopsis()
    
    if crash_encountered == False:
        dbg.suspend_all_threads()
        dbg.process_resotre()
        crash_encountered = True
        
        for thread_id in dbg.enumerate_threads():
            
            print "[*] Setting single step for thread: 0x%08x" % thread_id
            h_thread = dbg.open_thread(thread_id)
            dbg.single_step(True, h_thread)
            dbg.close_handle(h_thread)  
            
    else:
        dbg.terminate_process()
        return DBG_EXCEPTION_NOT_HANDLED

def single_step_handler(dbg):
    global instruction_count
    global crash_encoutered

    if crash_encountered:
        
        if instruction_count == MAX_INSTRUCTIONS:

            dbg.single_step(False)

        else:

            instruction = dbg.diasm(dbg.context.Eip)
            print "#%d\t0x%08x : %s" % (instruction_count,dbg.context.Eip,instruction)
            instruction_count += 1
            dbg.single_step(True)

    return DBG_CONTINUE

dbg = pydbg()

pid = int(raw_input("Enter the PID you with to monitor: "))
dbg.attach(pid)

for func in dangerous_functions.keys():

    func_address = dbg.func_resolve(dangerous_functions[func],func)
    print "[*] Resolved breakpoint: %s -> 0x%08x" % (func, func_address)
    dbg.bp_set(func_address, handler = danger_handler)
    dangerous_functions_resolved[func_address] = func

dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, access_violation_handler)
dbg.set_callback(EXCEPTION_SINGLE_STEP, single_step_handler)
dbg.run()
