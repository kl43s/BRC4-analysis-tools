import idautils
import idc
import idaapi
import time 


print('''###############
#    START    #
###############
''')

for func in idautils.Functions():
    for instruction in idautils.Heads(func, idc.get_func_attr(func, idc.FUNCATTR_END)):
        True
        
instruction += 1
start_address = instruction

instructions = []
for i, addr in enumerate(idautils.Heads(start_address, ida_ida.cvar.inf.max_ea)):
    mnem = idaapi.ua_mnem(addr)
    operand = idc.print_operand(addr, 0)
    operand2 = idc.print_operand(addr, 1)
    if operand2 != "":
        instructions.append(hex(addr) + ": " + mnem + " " + operand + ", " + operand2)
    elif mnem == "retn":
        break
    else:
        instructions.append(hex(addr) + ": " + mnem + " " + operand)
        

call_func = []
for i in instructions:
    if "call" in i:
        if "syscall" in i.split(': ')[1]:
            call_func.append(i.split(':')[0])
        elif len(i.split(': ')[1]) == 8:
            call_func.append(i.split(':')[0])
            

addr_to_break = call_func[-1]
time.sleep(2)

idaapi.add_bpt(int(addr_to_break, base=16), 0, idaapi.BPT_DEFAULT)
idaapi.load_debugger("windbg", 1)
idaapi.start_process(ida_nalt.get_input_file_path(), "", "")
idaapi.continue_process()


ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
rsp_value = idaapi.get_reg_val("RSP")

addr = 0
while hex(addr) != "0x20000":
    rsp_value += 8
    addr = idaapi.get_bytes(rsp_value, 8)
    addr = struct.unpack("<Q", addr)[0]
    print(hex(addr))

print( idaapi.get_bytes(addr, 256) )

idaapi.exit_process()


print('''#############
#    END    #
#############
''')
