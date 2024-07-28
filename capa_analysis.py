import json
import subprocess
import os
import time

class CapaData:
    def __init__(self, sample, sigs_path, rules_path):
        self.sample = sample
        self.sigs_path = sigs_path
        self.rules_path = rules_path


    def run(self):
        try:
            json_file = self.sample.split('.')[0]+'.json'
            output = {}
            p = subprocess.Popen(['capa', '-s', self.sigs_path, '-r', self.rules_path, '-j', self.sample], stdout=subprocess.PIPE)
            while p.poll() is None:
                print("Process is still running")
                time.sleep(1)
            print("Process finished with exit code:", p.returncode)
            if(p.returncode == 0 and os.path.isfile(json_file)):
                with open(json_file, 'r') as f:
                    data = json.load(f)
                for i in data['rules']:
                    attack = data['rules'][i]['meta']['attack']
                    if(len(attack)):
                        for j in attack:
                            tactic = j['tactic']
                            if(tactic in output):
                                output[tactic].append({'name': data['rules'][i]['meta']['name'], 'technique': j['technique'], 'subtechnique': j['subtechnique'], 'id':j['id']})
                            else:
                                output[tactic] = []
                                output[tactic].append({'name': data['rules'][i]['meta']['name'], 'technique': j['technique'], 'subtechnique': j['subtechnique'], 'id':j['id']})
                    
                    mbc = data['rules'][i]['meta']['mbc']
                    if(len(mbc)):
                        for j in mbc:
                            objective = j['objective']
                            if(objective in output):
                                output[objective].append({'name': data['rules'][i]['meta']['name'], 'objective': j['objective'], 'behavior': j['behavior'], 'id':j['id']})
                            else:
                                output[objective] = []
                                output[objective].append({'name': data['rules'][i]['meta']['name'], 'objective': j['objective'], 'behavior': j['behavior'], 'id':j['id']})
                    
                    #Need to work on below code part its incomplete.
                    '''if(not len(attack) and not len(mbc)):
                        if('capability' in output):
                            try:
                                output['capability'].append({'name': data['rules'][i]['meta']['name'], 'namespace': data['rules'][i]['meta']['namespace'], 'matches': len(data['rules'][i]['meta'])})
                            except:
                                output['capability'].append({'name': data['rules'][i]['meta']['name'], 'matches': len(data['rules'][i]['meta'])})
                        else:
                            try:
                                output['capability'] = []
                                output['capability'].append({'name': data['rules'][i]['meta']['name'], 'namespace': data['rules'][i]['meta']['namespace'], 'matches': len(data['rules'][i]['meta'])})
                            except:
                                output['capability'].append({'name': data['rules'][i]['meta']['name'], 'matches': len(data['rules'][i]['meta'])})
                    '''

            return output



        except OSError as e:
            print('Execution Failed: ', e)

