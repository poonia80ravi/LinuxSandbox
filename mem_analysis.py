import os
import subprocess
import json

class MemoryAnalysis:
    def __init__(self, python3_path, vol3_path, mem_file, symbol_dir):
        self.mem_file = mem_file
        self.symbol_dir = symbol_dir
        self.vol3 = vol3_path
        self.python3= python3_path

    def run_cmd(self, cmd):
        proc = subprocess.Popen([self.python3, self.vol3, '-f', self.mem_file, '-s', self.symbol_dir, '-r', 'json', cmd], stdout=subprocess.PIPE)
        return proc.communicate()[0]
    #Lists the processes present in a particular linux memory image.
    def pslist(self):
        dic = json.loads(self.run_cmd('linux.pslist.PsList').decode())
        return dic

    #Recovers bash command history from memory.
    def bash(self):
        dic = json.loads(self.run_cmd('linux.bash.Bash').decode())
        return dic
    
    #Verifies the operation function pointers of network protocols.
    def check_afinfo(self):
        dic = json.loads(self.run_cmd('linux.check_afinfo.Check_afinfo'))
        return dic
    
    #Checks if any processes are sharing credential structures.
    def check_creds(self):
        dic = json.loads(self.run_cmd('linux.check_creds.Check_creds'))
        return dic

    #Checks if the IDT has been altered.
    def check_idt(self):
        dic = json.loads(self.run_cmd('linux.check_idt.Check_idt'))
        return dic
    
    #Compares module list to sysfs info, if available
    def check_modules(self):
        dic = json.loads(self.run_cmd('linux.check_modules.Check_modules'))
        return dic

    #Check system call table for hooks.
    def check_syscall(self):
        dic = json.loads(self.run_cmd('linux.check_syscall.Check_syscall'))
        return dic
    #Lists all memory mapped ELF files for all processes.
    def elfs(self):
        dic = json.loads(self.run_cmd('linux.elfs.Elfs'))
        return dic
    #Lists processes with their environment variables

    def envvars(self):
        dic = json.loads(self.run_cmd('linux.envvars.Envvars'))
        return dic
    # Generates an output similar to /proc/iomem on a running system.
    def iomem(self):
        dic = json.loads(self.run_cmd('linux.iomem.IOMem'))
        return dic
    # Parses the keyboard notifier call chain
    def keyboard_notifiers(self):
        dic = json.loads(self.run_cmd('linux.keyboard_notifiers.Keyboard_notifiers'))
        return dic
    # Kernel log buffer reader
    def kmsg(self):
        dic = json.loads(self.run_cmd('linux.kmsg.Kmsg'))
        return dic
    # Lists loaded kernel modules.
    def lsmod(self):
        dic = json.loads(self.run_cmd('linux.lsmod.Lsmod'))
        return dic
    # Lists all memory maps for all processes.
    def lsof(self):
        dic = json.loads(self.run_cmd('linux.lsof.Lsof'))
        return dic
    # Lists process memory ranges that potentially contain injected code.
    def malfind(self):
        dic = json.loads(self.run_cmd('linux.malfind.Malfind'))
        return dic
    # Lists mount points on processes mount namespaces
    def mountinfo(self):
        dic = json.loads(self.run_cmd('linux.mountinfo.MountInfo'))
        return dic
    # Lists all memory maps for all processes.
    def proc_maps(self):
        dic = json.loads(self.run_cmd('linux.proc.Maps'))
        return dic
    # Lists processes with their command line arguments
    def psaux(self):
        dic = json.loads(self.run_cmd('linux.psaux.PsAux'))
        return dic
    # Scans for processes present in a particular linux image.
    def psscan(self):
        dic = json.loads(self.run_cmd('linux.psscan.PsScan'))
        return dic
    # Plugin for listing processes in a tree based on their parent process ID.
    def pstree(self):
        dic = json.loads(self.run_cmd('linux.pstree.PsTree'))
        return dic
    # Lists all network connections for all processes.
    def sockstat(self):
        dic = json.loads(self.run_cmd('linux.sockstat.SockStat'))
        return dic
    # Checks tty devices for hooks
    def tty_check(self):
        dic = json.loads(self.run_cmd('linux.tty_check.tty_check'))
        return dic



'''
python_path = '/usr/bin/python3'
vol_path = '/home/poonia/Documents/volatility3/vol.py'
symbol_dir = os.popen('pwd').read()+'/vol_symbols/'
mem_file = 'remnux.vmem'
print(symbol_dir)

final_dict = {}
m = MemoryAnalysis(python_path, vol_path, mem_file, symbol_dir)
final_dict['pslist'] = m.pslist()

final_dict['bash'] = m.bash()
#final_dict['check_afinfo'] = m.check_afinfo()
final_dict['check_creds'] = m.check_creds()
final_dict['check_idt'] = m.check_idt()
final_dict['check_models'] = m.check_modules()
final_dict['check_syscall'] = m.check_syscall()
final_dict['elfs'] = m.elfs()
final_dict['envvars'] = m.envvars()
#final_dict['iomem'] = m.iomem()
final_dict['keyboard_notifiers'] = m.keyboard_notifiers()
#final_dict['kmsg'] = m.kmsg()
final_dict['lsmod'] = m.lsmod()
final_dict['lsof'] = m.lsof()
final_dict['malfind'] = m.malfind()
final_dict['mountinfo'] = m.mountinfo()
final_dict['proc_maps'] = m.proc_maps()
final_dict['psaux'] = m.psaux()
final_dict['psscan'] = m.psscan()
final_dict['pstree'] = m.pstree()
#final_dict['sockstat'] = m.sockstat()
final_dict['tty_check'] = m.tty_check()


with open('remnux_memory_dump_analysis.json', 'w') as f:
    json.dump(final_dict, f)
'''
