import os
import re
import sys
import json
import subprocess


class SysdigParser:
    def __init__(self, filename):
        self.scap_file = filename
        self.sysdig_data = None
    def read_scap(self):
        dic = []
        proc = subprocess.Popen(['sysdig', '-j', '-r', self.scap_file], stdout=subprocess.PIPE)
        output = proc.communicate()[0].decode()
        for i in output.split('\n'):
            if(len(i)>1):
                data = json.loads(i)
                evt_id = data['evt.num']
                del data['evt.num']
                #dic[evt_id] = data
                dic.append(data)
        return dic
    
    def delim(self, arguments):
        d = {}
        ptid = r"(ptid=\d+)"
        if('exe=' in arguments):
            start = arguments.find('exe=')
            end = arguments.find('args=')
            d['exe'] = arguments[start+4:end]

            start = arguments.find('args=')
            end = arguments.find('tid=')
            d['args'] = arguments[start+5:end]
            
            d['ptid'] = re.findall(ptid, arguments)[0].split('=')[1]


        elif('filename=' in arguments):
            start = arguments.find('filename=')
            end = arguments.find('tid=')
            d['filename'] = arguments[start+9:end]
            #d['ptid'] = re.findall(ptid, arguments)
        else:
            d['raw'] = arguments
        
        return d

        


    def processCreated(self):
        self.sysdig_data = self.read_scap()
        d = {}
        process_syscall = ['fork', 'vfork', 'exec', 'execl', 'execlp', 'execv', 'execvp', 'execle', 'execve', 'clone']
        for i in self.sysdig_data:
            syscall = i['evt.type']
            evt_dir = i['evt.dir']
            if(syscall in process_syscall and evt_dir == '<'):
                
                if(i['thread.tid'] not in d):
                    d[i['thread.tid']] = []
                if(i['evt.info'] != ''):
                    da = self.delim(i['evt.info'])
                    da['process_name'] = i['proc.name']
                    da['syscall'] = syscall
                    if(da not in d[i['thread.tid']]):
                        d[i['thread.tid']].append(da)          
        return d
    
    def open_call_delim(self, syscall, arguments):
        # fd=-2(ENOENT) dirfd=-100(AT_FDCWD) name=/usr/share/locale/en/LC_MESSAGES/coreutils.mo flags=1(O_RDONLY) mode=0 dev=0 
        data = {}
        d = arguments.split(' ')
        for i in d:
            if('=' in i):
                da = i.split('=', 1)
                if(da[0] == 'fd'):
                    temp = da[1].split('(')[0].strip()
                    if(int(temp) > 2):
                        data[da[0]] = da[1]
                else:
                    data[da[0]] = da[1]
        return data


    def read_files(self):

        #regex to get the file name only from the file descriptor.
        pattern = r"^.*\(<f>(.*)\)$"

        file_ops = {}
        self.sysdig_data = self.read_scap()

        access_check = 0
        access_mode = ''

        # Open or create a file.
        read_call = ['openat', 'open', 'creat', 'openat2']
        for i in self.sysdig_data:
            syscall = i['evt.type']
            evt_dir = i['evt.dir']
            tid = i['thread.tid']
            if(tid not in file_ops):
                file_ops[tid] = {}
                #file_ops[tid]['opened'] = []
                file_ops[tid]['read'] = []
                file_ops[tid]['written'] = []
                file_ops[tid]['deleted'] = []
                file_ops[tid]['rename'] = []
                file_ops[tid]['access'] = []
                file_ops[tid]['change_permission'] = []
            if(syscall in read_call and evt_dir == '<'):
                data = self.open_call_delim(syscall, i['evt.info'])
                data['process_name'] = i['proc.name']
                try:
                    if('O_RDONLY' in data['flags']):
                        file_ops[tid]['read'].append(data['name'])
                    elif():
                        file_ops[tid]['written'].append(data['name'])
                except:
                    file_ops[tid]['read'].append(data)

            #Read file
            elif((syscall == 'read' or syscall == 'pread') and evt_dir == '>'):
                data = self.open_call_delim(syscall, i['evt.info'])
                data['process_name'] = i['proc.name']
                try:
                    read_filename = ''
                    match = re.match(pattern, data['fd'])
                    if match:
                        read_filename = match.group(1)
                    if(read_filename and (read_filename not in file_ops[tid]['read'])):
                        file_ops[tid]['read'].append(read_filename)
                except:
                    file_ops[tid]['read'].append(data)
            #Write files
            elif((syscall == 'write') and evt_dir == '>'):
                index = self.sysdig_data.index(i)
                data = self.open_call_delim(syscall, i['evt.info'])
                try:
                    if('fd' in data):
                        temp = int(data['fd'].split('(')[0].strip())
                        syscall = self.sysdig_data[index+1]['evt.type']
                        evt_dir = self.sysdig_data[index+1]['evt.dir']
                        if(temp > 2 and syscall == 'write' and evt_dir == '<'):
                            data1 = self.open_call_delim(syscall, self.sysdig_data[index+1]['evt.info'])
                            data1['fd'] = data['fd']
                            data1['process_name'] = self.sysdig_data[index+1]['proc.name']
                            # file_ops[tid]['written'].append(data1)
                            # To get only filename write syscall 
                            write_filename = ''
                            match = re.match(pattern, data['fd'])
                            if match:
                                write_filename = match.group(1)
                            if(write_filename and (write_filename not in file_ops[tid]['written'])):
                                file_ops[tid]['written'].append(write_filename)
                except:
                    file_ops[tid]['written'].append(data)
            #Delete Files
            elif((syscall == 'unlink' or syscall == 'unlinkat') and evt_dir == '<'):
                index = self.sysdig_data.index(i)
                data = self.open_call_delim(syscall, i['evt.info'])
                try:
                    data['process_name'] = i['proc.name']
                    file_ops[tid]['deleted'].append(data['name'])
                except:
                    file_ops[tid]['deleted'].append(data)

            #Permission changed
            elif((syscall == 'chmod' or syscall == 'fchmodat' or syscall=='fchmod') and evt_dir == '<'):
                index = self.sysdig_data.index(i)
                data = self.open_call_delim(syscall, i['evt.info'])
                try:
                    data['process_name'] = i['proc.name']
                    file_ops[tid]['change_permission'].append({'filename':data['filename'], 'mode': data['mode']})
                except:
                    file_ops[tid]['change_permission'].append(data)
            
            elif((syscall == 'rename' or syscall == 'renameat' or syscall == 'renameat2') and evt_dir == '<'):
                index = self.sysdig_data.index(i)
                data = self.open_call_delim(syscall, i['evt.info'])
                try:
                    data['process_name'] = i['proc.name']
                    file_ops[tid]['rename'].append({'oldpath':data['oldpath'], 'newpath': data['newpath']})
                except:
                    file_ops[tid]['rename'].append(data)

            elif(syscall == 'access'):
                index = self.sysdig_data.index(i)
                data = self.open_call_delim(syscall, i['evt.info'])
                if(evt_dir == '>'):
                    access_check = 1
                    access_mode = data['mode']
                if(access_check and evt_dir=='<'):
                    try:
                        data['process_name'] = i['proc.name']
                        file_ops[tid]['access'].append({'name':data['name'], 'mode': access_mode})
                        access_mode = ''
                    except:
                        file_ops[tid]['access'].append(data)
                        access_mode = ''
            else:
                pass
        
        try:
            for i in file_ops:
                file_ops[i]['read'] = list(set(file_ops[i]['read']))
                file_ops[i]['written'] = list(set(file_ops[i]['written']))
                file_ops[i]['deleted'] = list(set(file_ops[i]['deleted']))
                file_ops[i]['rename'] = list(set(file_ops[i]['rename']))
                file_ops[i]['access'] = list(set(file_ops[i]['access']))
                file_ops[i]['change_permission'] = list(set(file_ops[i]['change_permission']))
        except Exception as err:
            pass

                
        return file_ops



'''
filename = sys.argv[1]
s = SysdigParser(filename)
syscall_filter_data ={}
syscall_filter_data['ProcessTree'] = s.processCreated()
syscall_filter_data['fileOperations'] = s.read_files()

with open('random.json', 'w') as f:
    json.dump(syscall_filter_data, f)
'''
