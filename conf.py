import os


#Update virtual machine data for running multiple vm machine

vm_data = {}
# Update the vm_data key as your vm machine name.
'''vm_data['REMnux'] = {}
vm_data['REMnux'] = {
        'vm_ip' : '192.168.6.101',
        'vm_interface' : 'vboxnet0',
        'snap_name' : 'remnux_snap3',
        'username' : 'remnux',
        'password' : '$(password)' 
        }'''
#Here ubuntu is the VM machine name.
vm_data['ubuntu'] = {}                        
vm_data['ubuntu'] = {
        #Update VM static Ip address.
        'vm_ip' : '192.168.56.106', 
        #Update VM network interface 
        'vm_interface' : 'vboxnet0',
        #Update the VM snapshot name.
        'snap_name': 'ubuntu_snap',
        #Update the VM machine username.
        'username' : 'ubuntu',
        #Update the VM machine password.
        'password' : 'malware'
        }



class Conf:
    def __init__(self, filename, machine, timeout):
        self.filename = filename
        self.machine = machine
        self.timeout = timeout
    
    def run(self):
        dic = {}
        pwd = os.getcwd()
        uname = os.path.expanduser('~')
        tmp = os.path.basename(self.filename).split('.')[0]
        if(not os.path.isdir(os.path.join(uname, 'linuxbox'))):
            os.mkdir(os.path.join(uname, 'linuxbox'))
        #path = pwd+'/'+tmp
        path = os.path.join(uname, 'linuxbox', tmp)
        if(not os.path.isdir(path)):
            os.mkdir(path)

        # File names which will be created during the analysis.
        dic['filename'] = os.path.basename(self.filename)
        dic['dir_path'] = path
        dic['log_filename'] = path+'/'+tmp[:15]+'.log'

        dic['scap_filename'] = path +'/'+tmp[:15]+'.scap'

        dic['pcap_filename'] = path+'/'+tmp[:15]+'.pcap'

        dic['report_filename'] = path+'/'+tmp[:15]+'_report.json'

        dic['vm_sysdig_chisel_output'] = path+'/'+tmp[:15]+'_chisel.txt'
        
        # Guest machine configuration
        dic['vm_ip'] = vm_data[self.machine]['vm_ip']
        dic['vm_interface'] = vm_data[self.machine]['vm_interface']
        dic['vm_name'] = self.machine
        dic['snap_name'] = vm_data[self.machine]['snap_name']
        dic['username'] = vm_data[self.machine]['username']
        dic['password'] = vm_data[self.machine]['password']
        dic['vm_scap_path'] = '/tmp/'+tmp[:15]+'.scap'
        
        # path of tcpdump and python in host machine
        dic['tcpdump_path'] = '/usr/bin/tcpdump'
        dic['python_path'] = '/usr/bin/python3'
        
        # Time in seconds, for how much time the malware will be running.
        dic['timeout'] = self.timeout
        
        #Configurations for memory forensics
        dic['vol_path'] = os.path.join(pwd, 'volatility3/vol.py')
        dic['symbol_dir'] = os.popen('pwd').read()+'/vol_symbols/'
        dic['vm_vmem_path'] = path+'/'+tmp[:15]+'.vmem'
        dic['dump_memory'] = 'No'
        
        #Capa tool configuration path of rules directory and signatures.
        dic['sigs_path'] = os.path.join(pwd, 'capa/sigs')
        dic['rules_path'] = os.path.join(pwd, 'capa-rules-4.0.0')
        dic['capa_filename'] = path+'/'+tmp[:15]+'_capa.json'

        return dic




