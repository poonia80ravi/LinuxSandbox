import os
import sys
import subprocess
import re
import jc
import time
import logging

#logger = logging.basicConfig(level=logging.DEBUG, format="%(asctime)s : %(levelname)s : %(message)s")

class VirtualBox:
    def __init__(self, sample, conf_data):
        self.sample = sample
        self.vm_sample_path = '/tmp/'+os.path.basename(self.sample)
        self.conf_data = conf_data
        self.vm_name = self.conf_data['vm_name']
        self.username = self.conf_data['username']
        self.password = self.conf_data['password']
        self.logger = logging.basicConfig(level=logging.DEBUG, filename=self.conf_data['log_filename'], format="%(asctime)s : %(levelname)s : %(message)s")
        print('Started Virtualbox!!!!')
    def start_vm(self):
        vm_state_timeout = 60
        try:
            self.vm_type = 'headless'
            proc = subprocess.Popen(['VBoxManage', 'startvm', self.vm_name, '--type', self.vm_type], stdout=subprocess.PIPE)
            vm_stdout, vm_stderr = proc.communicate()
            stop_me = 0
            while proc.poll() is None:
                if stop_me < vm_state_timeout:
                    time.sleep(1)
                    stop_me += 1
                else:
                    print("Starting vm timeouted. Killing", self.vm_name)
                    proc.terminate()

            if proc.returncode != 0 and stop_me < vm_state_timeout:
                vm_stdout, vm_stderr = proc.communicate()
                print(
                    "VBoxManage exited with error starting the "
                    "machine",vm_stderr)
                raise OSError(vm_stderr)
        except OSError as e:
            print("VBoxManage exited with error starting the machine", e)

    def status_vm(self):
        try:
            out = os.popen("VBoxManage list runningvms | grep "+self.vm_name+" | sed -r 's/^\"(.*)\".*$/\1/' | wc -l")
            return int(out.read().strip())
        except OSError as e:
            logging.error("Error while checking the status of vm machine. ", e)
    def stop_vm(self):
        vm_state_timeout = 60
        try:
            proc = subprocess.Popen(['VBoxManage','controlvm',self.vm_name,'poweroff', '--type', 'safepoweroff'], stdout=subprocess.PIPE)
            stop_me = 0
            while proc.poll() is None:
                if stop_me < vm_state_timeout:
                    time.sleep(1)
                    stop_me += 1
                else:
                    print("Stopping vm timeouted. Killing", self.vm_name)
                    proc.terminate()

            if proc.returncode != 0 and stop_me < vm_state_timeout:
                vm_stdout, vm_stderr = proc.communicate()
                print(
                    "VBoxManage exited with error powering off the "
                    "machine",vm_stderr)
                raise OSError(vm_stderr)
        except OSError as e:
            print("VBoxManage exited with error powering off the machine", e)


    def suspend_vm(self):
        proc = subprocess.Popen(['VBoxManage', 'controlvm', self.vm_name, 'suspend'], stdout=subprocess.PIPE)
        vm_stdout, vm_stderr = proc.communicate()[0]
        if proc.returncode:
            raise OSError("During suspend error code %d: %s" % (proc.returncode, vm_stderr))

    
    def restore_vm(self):
        #p = subprocess.Popen(['VBoxManage', 'modifyvm', self.vm_name, '--vrde', 'off'], stdout=subprocess.PIPE)

        self.snap_name = self.conf_data['snap_name']
        proc = subprocess.Popen(['VBoxManage', 'snapshot', self.vm_name, 'restore', self.snap_name], stdout=subprocess.PIPE)
        vm_stdout, vm_stderr = proc.communicate()
        if proc.returncode:
            raise OSError("During restore error code %d: %s" % (proc.returncode, vm_stderr))
    

    def copytovm(self):
        proc = subprocess.Popen(['VBoxManage', 'guestcontrol', self.vm_name, 'copyto', '--username', self.username, '--password', self.password, '--target-directory', self.vm_sample_path, self.sample])
        vm_stdout, vm_stderr = proc.communicate()
        if proc.returncode:
            raise OSError("While copying to vm error code %d: %s" % (proc.returncode, vm_stderr))
    
    def copyfromvm(self, target_dir, file_path):
        print('Trying to move a {} to a directory {}.'.format(file_path, target_dir))
        proc = subprocess.Popen(['VBoxManage', 'guestcontrol', self.vm_name, 'copyfrom', '--username', self.username, '--password', self.password, '--target-directory', target_dir, file_path])
        vm_stdout, vm_stderr = proc.communicate()
        if proc.returncode:
            raise OSError("While copying from vm error code %d: %s" % (proc.returncode, vm_stderr))

    
    def change_permissions(self):
        #self.sample_path = '/tmp/'+self.sample
        proc = subprocess.Popen(['VBoxManage', 'guestcontrol', self.vm_name, 'run', '--exe', '/bin/chmod', '--username', self.username, '--password', self.password, '--', '0755', self.vm_sample_path])
        vm_stdout, vm_stderr = proc.communicate()
        if proc.returncode:
            #p = subprocess.Popen(['VBoxManage', 'guestcontrol', self.vm_name, 'run', '--exe', '/bin/chmod', '--username', 'remnux', '--password', 'malware', '--','chmod', '+x', self.sample_path])
            raise OSError("During permission change error code %d: %s" % (proc.returncode, vm_stderr))
    
    def execute_sample(self):
        #self.sample_path = '/tmp/'+self.sample
        proc = subprocess.Popen(['VBoxManage', 'guestcontrol', self.vm_name, 'run', '--exe', '/bin/sh', '--username', 'root', '--password', 'malware', '--','-c', self.vm_sample_path])
        #vm_stdout, vm_stderr = proc.communicate()
        if proc.returncode:
            raise OSError("During execution of sample error code %d:" % (proc.returncode))
        
    
    def list_guest_processes(self):
        
        list_process = subprocess.Popen(['VBoxManage', 'guestcontrol', self.vm_name, 'run', '--exe', '/bin/ps', '--username', self.username, '--password', self.password, '--', 'aux'], stdout=subprocess.PIPE)
        processes = list_process.communicate()[0]
        process_list = processes.decode()
        data = jc.parse('ps', process_list)
        return data
        '''l_process = subprocess.Popen(['VBoxManage', 'guestcontrol', self.vm_name, 'run', '--exe', '/bin/ps', '--username', 'remnux', '--password', 'malware', '--wait-stdout', '--', 'listProcessesInGuest'], stdout=subprocess.PIPE)
        p = l_process.communicate()[0]
        print(p)'''


    def execute_sysdig(self, filter_file_name):
        try:
            out_scap_file = self.conf_data['vm_scap_path']
            print('Writing the sysdig data to ', out_scap_file)
            cap_filter = "proc.name=" + filter_file_name[:15] + " " + "or proc.aname=" + filter_file_name[:15]
            list_process = subprocess.Popen(['VBoxManage', 'guestcontrol', self.vm_name, 'run', '--exe', '/usr/bin/sysdig','--username', 'root', '--password', 'malware', '--wait-stdout', '--',cap_filter, '-w', out_scap_file ], stdout=subprocess.PIPE)
            list_processes = self.list_guest_processes()
            for i in list_processes:
                if(filter_file_name in i['command']):
                    self.loggger.info('Sysdig process found ', i['command'])
        except Exception as err:
            if(self.status_vm()):
                self.stop_vm()
            #print('Error while executing sysdig: ', err)

    def execute_sysdig_chisel(self, filter_file_name):
        try: 
            output_file = self.conf_data['vm_sysdig_chisel_output']
            print('Writing the sysdig chisel data to ', output_file)
            f = open(output_file, 'w')
            cap_filter = "proc.name=" + filter_file_name[:15] + " " + "or proc.aname=" + filter_file_name[:15]
            list_process = subprocess.Popen(['VBoxManage', 'guestcontrol', self.vm_name, 'run', '--exe', '/usr/bin/sysdig','--username', 'root', '--password', 'malware', '--wait-stdout', '--','-A', '-c', 'echo_fds', cap_filter], stdout=f)
            print(list_process)
            return list_process
        except Exception as err:
            print(err)
            #print('Error: ',err)
            

    def stop_sysdig(self, process_name):
        try:
            list_process = self.list_guest_processes()
            proc = {}
            #print(list_process)
            for i in list_process:
                if(process_name in i['command']):
                    proc[i['pid']] = i['command']
            print('sysdig process running inside vm machine: ',proc)
        
            p = r"([P]*ID=\d+)"
            c_proc=subprocess.Popen(['VBoxManage','guestcontrol',self.vm_name,'list','all'],stdout=subprocess.PIPE)
            vm_op=((c_proc.communicate()[0]).decode())
            print(vm_op)
            pid_sessid = re.findall(p, vm_op)
            pid_sessid_dict={}
            for pid in range(0,len(pid_sessid)-1,2):
                pid_sessid_dict[(pid_sessid[pid+1][4:len(pid_sessid[pid+1])]).strip()]=(pid_sessid[pid][3:len(pid_sessid[pid])]).strip()
            print(pid_sessid_dict)
            for proc_id in pid_sessid_dict:
                print(proc_id)
                proc_sessid=pid_sessid_dict[proc_id]
                print(proc_sessid)
                kill_proc=subprocess.check_call(['VBoxManage','guestcontrol',self.vm_name,'closeprocess','--session-id',proc_sessid,proc_id])
                print(kill_proc)
        except Exception as err:
            if(self.status_vm()):
                self.stop_vm()
            print('Error while stopping sysdig: ', err)


    def dump_mem(self):
        try:
            dump_filename = self.conf_data['vm_vmem_path']
            cmd = '--filename='+dump_filename
            proc = subprocess.Popen(['VBoxManage', 'debugvm', self.vm_name, 'dumpvmcore', cmd], stdout=subprocess.PIPE)
            vm_stdout, vm_stderr = proc.communicate()
        except Exception as err:
            if(self.status_vm()):
                self.stop_vm()
            print('Error while dumping the memory: ', err)





class TcpDump:
    def __init__(self, conf_data):
        self.conf_data = conf_data
        self.vm_ip = self.conf_data['vm_ip']
        self.interface = self.conf_data['vm_interface']
        self.proc = None
        self.tcpdump_path = self.conf_data['tcpdump_path']
        self.tcpdump_output_path = self.conf_data['pcap_filename']
        self.logger = logging.basicConfig(level=logging.DEBUG, filename=self.conf_data['log_filename'], format="%(asctime)s : %(levelname)s : %(message)s")

    def start_tcpdump(self, tcpdump_path, tcpdump_output_path):
        self.proc=subprocess.Popen([self.tcpdump_path,'-n','-i',self.interface,'host %s'%self.vm_ip,'-w', self.tcpdump_output_path])
        
        return self.proc.pid
    def stop_tcpdump(self):
        if(self.proc != None):
            print('Terminating TCPDUMP....')
            self.proc.terminate()
            print('Terminated..!!')
        else:
            print("TCPDUMP was not spawned")
    
    def dnsSummaryReport(self):
        c_proc = subprocess.Popen([self.tcpdump_path, '-n', '-r', self.tcpdump_output_path, "udp and port 53"], stdout=subprocess.PIPE)
        dns_query_summary= (c_proc.communicate()[0]).decode()
        return dns_query_summary
    
    def tcpConversationReport(self):
        c_proc = subprocess.Popen([self.tcpdump_path,'-n', '-q', '-r', self.tcpdump_output_path, "tcp"], stdout=subprocess.PIPE)
        tcp_conv_summary= (c_proc.communicate()[0]).decode()
        return tcp_conv_summary


'''filename = sys.argv[1]
vm = VirtualBox(filename)
tcpdump = TcpDump('192.168.56.105', 'vboxnet0')
vm.stop_vm()
vm.restore_vm()
print('Restored the virtual machine')
vm.start_vm()
print('Started the virtual machine')

vm.copytovm()
print('Executable copied to vm machine')

vm.change_permissions()
print('Executables permissions changed')
pid = tcpdump.start_tcpdump('/usr/bin/tcpdump', '/home/poonia/Documents/linux_sandbox/abc.pcap')
print(pid)
vm.execute_sysdig(filename)
print('Executing sysdig tool!')
vm.execute_sample()
print('Sample Executed sucessfully!')
#print(vm.list_guest_processes())
vm.stop_sysdig('sysdig')
tcpdump.stop_tcpdump()
scap_file = filename+'.scap'
vm.copyfromvm('/home/poonia/Documents/linux_sandbox/', '/home/remnux/'+scap_file)
vm.dump_mem()
print('Successfully dumped the memory!')
vm.stop_vm()'''
