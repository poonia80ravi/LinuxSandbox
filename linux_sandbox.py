import logging
from virtual_box import VirtualBox
from virtual_box import TcpDump
from syscall import SysdigParser
from static_analysis import StaticAnalysis
from conf import Conf, vm_data
from capa_analysis import CapaData 
from elftools.elf.elffile import ELFFile
from mem_analysis import MemoryAnalysis
from io import BytesIO, open
from network import jsonParserNetwork 
from db import Database
import json
import random
import sys
import os
import shutil
import time
import datetime
import argparse
import concurrent.futures


machine_aval = {}
for i in vm_data:
    machine_aval[i] = 'available'




def analysis(filename):
    
    #print(filename)
    final_data = {}

    # Static Analysis
    with open(filename, 'rb') as f:
        data = f.read()


    static_data = {}
    elf = ELFFile(BytesIO(data))

    static_analysis = StaticAnalysis(elf)
    static_data['Header'] = static_analysis.headers()
    static_data['Segments'] = static_analysis.segments()
    static_data['Sections'] = static_analysis.sections()
    static_data['Symbols'] = static_analysis.symbols()
    static_data['Shared Libaries'] = static_analysis.dynamic()
    static_data['Section Segment Mapping'] = static_analysis.section_segment_mapping()

    final_data['StaticAnalysis'] = static_data

    # Behaviour Analysis

    sleep_time = random.uniform(0, 1)
    time.sleep(sleep_time)

    db = Database() 
    # Selection of virtual machine as per user. 
    vm_mch = db.sql_query_data("SELECT vm_machine FROM tasks WHERE filename='"+filename+"';")[0][0]
    time_out = db.sql_query_data("SELECT timeout FROM tasks WHERE filename='"+filename+"';")[0][0]
    if(not vm_mch):
        #Check for the availablity of the vm machine
        machine_aval = db.sql_query_data("SELECT machine FROM machines WHERE availability='available';")
        for mac in machine_aval:
            db.sql_query_commit("UPDATE machines SET availability='assigned' WHERE machine='"+mac[0]+"';")
            vm_mch = mac[0]
            db.sql_query_commit("UPDATE tasks SET vm_machine='"+mac[0]+"' WHERE filename='"+filename+"';")
            break

        # If no machine is available to assign in that case have to wait upto when the machine is available.
            # Have to write the code.

    else:
        while True:
            machine_aval = db.sql_query_data("SELECT machine FROM machines WHERE availability='available';")
            machine_avals = []
            for i in machine_aval:
                if(i[0] not in machine_avals):
                    machine_avals.append(i[0])
            if(vm_mch in machine_avals):
                break
        #else:
        #    print('You have entered wrong virtual machine name!')
    
    #print(machine_aval)

    conf = Conf(filename, vm_mch, time_out)
    conf_data = conf.run()

    logging.basicConfig(level=logging.DEBUG, filename=conf_data['log_filename'], format="%(asctime)s : %(levelname)s : %(message)s")
    
    vm = VirtualBox(filename, conf_data)

    status = vm.status_vm()
    print('VM status is: ', status)
    db.sql_query_commit("UPDATE tasks SET status='Running' WHERE filename='"+filename+"';")
    started_on = datetime.datetime.now().timestamp()
    db.sql_query_commit("UPDATE tasks SET started_on=TO_TIMESTAMP("+str(started_on)+") WHERE filename='"+filename+"';")
    tcpdump = TcpDump(conf_data)

    if(status > 0):
        vm.stop_vm()

    vm.restore_vm()
    logging.info('Restored the virtual machine')
    vm.start_vm()
    logging.info('Started the virtual machine')
    time.sleep(5)
    vm.copytovm()
    print('copied file to vm')
    logging.info('Executable copied to vm machine')

    vm.change_permissions()
    logging.info('Executables permissions changed')
    pid = tcpdump.start_tcpdump(conf_data['tcpdump_path'], conf_data['pcap_filename'])
    logging.info(pid)
    vm.execute_sysdig(conf_data['filename'])
    logging.info('Executing sysdig tool to collect all syscalls!')
    vm.execute_sysdig_chisel(conf_data['filename'])
    logging.info('Executing sysdig tool!')
    vm.execute_sample()
    logging.info('Sample Executed sucessfully!')
    #print(vm.list_guest_processes())
    time.sleep(time_out)
    vm.stop_sysdig('sysdig')
    tcpdump.stop_tcpdump() 
    vm.copyfromvm(conf_data['scap_filename'], conf_data['vm_scap_path'])
    
    network_dict = {}
    dns_summary = tcpdump.dnsSummaryReport()
    json_parser = jsonParserNetwork()
    network_dict['DNS Summary'] = json_parser.parseDnsTraffic(dns_summary)

    tcp_conversation = tcpdump.tcpConversationReport()
    network_dict['TCP Summary'] = json_parser.parseTcpTraffic(tcp_conversation)
    final_dict = {}
    if(conf_data['dump_memory'] == 'Yes'):
        vm.dump_mem()
    
        logging.info('Successfully dumped the memory!')

        if(os.path.exists(conf_data['vm_vmem_path'])):
            final_dict = {}
            m = MemoryAnalysis(conf_data['python_path'], conf_data['vol_path'], conf_data['vm_vmem_path'], conf_data['symbol_dir'])
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
            #final_data['BehaviourAnalysis'] = {}
            #final_data['BehaviourAnalysis']['MemoryAnalysis'] = final_dict
        else:
            print('File doesnot exists')

    #c = CapaData(filename, conf_data['sigs_path'], conf_data['rules_path'])
    #final_data['BehaviourAnalysis']['Mitre ATT&CK Tactics and Techniques'] = c.run()
    
    final_data['DynamicAnalysis'] = {}


    status = vm.status_vm()

    if(status > 0):
        vm.stop_vm()
    
    completed_on = datetime.datetime.now().timestamp()
    db.sql_query_commit("UPDATE tasks SET started_on=TO_TIMESTAMP("+str(completed_on)+") WHERE filename='"+filename+"';")
    db.sql_query_commit("UPDATE tasks SET status='completed' WHERE filename='"+filename+"';")
    
    db.sql_query_commit("UPDATE machines SET availability='available' WHERE machine='"+vm_mch+"';")
    #machine_aval[vm_mch] = 'available'
    #print(machine_aval)
    if(os.path.exists(conf_data['scap_filename'])):
        s = SysdigParser(conf_data['scap_filename'])
        syscall_filter_data ={}
        syscall_filter_data['ProcessTree'] = s.processCreated()
        syscall_filter_data['fileOperations'] = s.read_files()
        final_data['DynamicAnalysis']['BehaviourAnalysis'] = syscall_filter_data

    c = CapaData(filename, conf_data['sigs_path'], conf_data['rules_path'])
    final_data['DynamicAnalysis']['BehaviourAnalysis']['Mitre ATT&CK Tactics and Techniques'] = c.run()
    final_data['DynamicAnalysis']['BehaviourAnalysis']['MemoryAnalysis'] = final_dict
    final_data['DynamicAnalysis']['NetworkAnalysis'] = network_dict
    with open(conf_data['report_filename'], 'w') as f:
        json.dump(final_data, f)
    db.sql_query_commit("UPDATE tasks SET status='reported' WHERE filename='"+filename+"';")

def clean_directory(directory_path):
    try:
        with os.scandir(directory_path) as entries:
            for entry in entries:
                if entry.is_file():
                    os.unlink(entry.path)
                else:
                    shutil.rmtree(entry.path)
    except OSError:
        print("Error occurred while deleting {}".format(directory_path))



def threading(pending_tasks):
    max_thread = len(vm_data)
    #machine_aval = {}
    db = Database()
    for machine in vm_data:
        id = db.sql_query_data("SELECT COUNT(*) FROM machines;")[0][0]
        query = "INSERT INTO machines VALUES ("+str(id)+", '"+machine+"', 'available');"
        db.sql_query_commit(query)

    #print(pending_tasks)
    with concurrent.futures.ProcessPoolExecutor(max_workers = max_thread) as executor:
        result = {executor.submit(analysis, filename): filename for filename in pending_tasks}
            #print('Completed the analysis of the %s file', filename)
    



def main(command_line=None):
    db = Database()

    parser = argparse.ArgumentParser()
    parser.add_argument('submit',action='store_true', help='Storing the files you want analyze in the sandbox.')
    subparsers = parser.add_subparsers(dest='command')
    submit_parser = subparsers.add_parser('submit', help='Submit the file to analyse.')
    submit_parser.add_argument('--filename',help='add the Files to analyze.', type=str, required=True, nargs='+')
    submit_parser.add_argument('--machine', help='Virtual machine name where you want to analyze.',type=str)
    submit_parser.add_argument('--timeout', help='For how many seconds you want run the malicious file', type=int, default=60)
    #submit_args = submit_parser.parse_args()
    parser.add_argument('init', action='store_true', help='Requires when initially setup the sandbox.')
    init_parser = subparsers.add_parser('init', help='For initial setup of sandbox.')
    parser.add_argument('clean', action='store_true', help='Clear the database entries and files from the analysis directory.')
    clear_parser = subparsers.add_parser('clean', help='clear all the file to analyse.')
    parser.add_argument('run', action='store_true', help='Run the sandbox.')
    run_parser = subparsers.add_parser('run', help='Running the sandbox')
    args = parser.parse_args(command_line)
    #Delete the entries and files

    if(args.command == 'init'):
        task_query = "CREATE TABLE tasks (\
                    id SERIAL PRIMARY KEY,\
                    filename VARCHAR(255) NOT NULL,\
                    vm_machine VARCHAR(50),\
                    status VARCHAR(50) NOT NULL,\
                    timeout INTEGER,\
                    added_on TIMESTAMP,\
                    started_on TIMESTAMP,\
                    completed_on TIMESTAMP\
                );"

        try:
            db.sql_query_commit("DROP TABLE IF EXISTS tasks;")
            db.sql_query_commit(task_query)
            db.sql_query_commit("DROP TABLE IF EXISTS machines;")
            db.sql_query_commit("CREATE TABLE machines (id SERIAL PRIMARY KEY, machine VARCHAR(50),availability VARCHAR(50) NOT NULL);")
        except:
            pass

    if(args.command == 'clean'):
        db.sql_query_commit("DELETE FROM tasks;")
        db.sql_query_commit("DELETE FROM machines;")
        username = os.path.expanduser('~')
        path = os.path.join(username, 'linuxbox')
        if(os.path.isdir(path)):
            clean_directory(path)

    if(args.command == 'submit'):
        if(args.machine):
            for i in args.filename:
                filename = i
                id = db.sql_query_data("SELECT COUNT(*) FROM tasks;")[0][0]
                machine = args.machine
                started_on = datetime.datetime.now().timestamp()
                query = "INSERT INTO tasks VALUES ("+str(id)+", '"+filename+"', '"+str(machine)+"', 'pending', '"+str(args.timeout)+"', TO_TIMESTAMP("+str(started_on)+"), Null, Null);"
                db.sql_query_commit(query)
                db.check_status()
        else:
            for i in args.filename:
                filename = i
                id = db.sql_query_data("SELECT COUNT(*) FROM tasks;")[0][0]
                added_on = datetime.datetime.now().timestamp()
                query = "INSERT INTO tasks VALUES ("+str(id)+", '"+filename+"', Null, 'pending', '"+str(args.timeout)+"', TO_TIMESTAMP("+str(added_on)+"), Null, Null);"
                db.sql_query_commit(query)
                db.check_status()



    '''parser.add_argument('--clear', action='store_true', help='Clear the database entries and files from the analysis directory.')
    parser.add_argument('--run', action='store_true', help='Run the sandbox.')
    args = parser.parse_args()
    #Delete the entries and files
    if(args.clear):
        db.sql_query_commit("DELETE FROM tasks;")
        db.sql_query_commit("DELETE FROM machines;")'''

    if(args.command == 'run'):
        while(True):
            pending_task = db.sql_query_data("SELECT filename FROM tasks WHERE status='pending';")
            pending_tasks = []
            for i in pending_task:
                pending_tasks.append(i[0])
            #print(pending_tasks)
            #print(db.check_status())
            if(len(pending_tasks) > 0):
                threading(pending_tasks)
            time.sleep(1)





if __name__ == '__main__':
    main()

