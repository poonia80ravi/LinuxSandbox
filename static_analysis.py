import os
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.descriptions import describe_sh_flags, describe_p_flags, describe_symbol_type, describe_e_type, describe_e_version_numeric, describe_e_machine, describe_ei_osabi, describe_ei_version, describe_ei_data, describe_ei_class
from elftools.elf.dynamic import DynamicSection
from io import BytesIO, open
import json

class StaticAnalysis():

    def __init__(self, elf):
        self.elf = elf

    def headers(self):
        dic = {}
        e_ident = self.elf.header['e_ident']
        dic['Type'] = describe_e_type(self.elf.header['e_type'])
        dic['Header_Version'] = describe_ei_version(e_ident['EI_VERSION'])
        dic['num_prog_headers'] = self.elf.header['e_phnum']
        dic['os_abi'] = describe_ei_osabi(e_ident['EI_OSABI'])
        dic['obj_version'] = describe_e_version_numeric(self.elf.header['e_version'])
        dic['Machine'] = describe_e_machine(self.elf.header['e_machine'])
        dic['entrypoint'] = hex(self.elf.header['e_entry'])
        dic['num_section_headers'] = self.elf.header['e_shnum']
        dic['abi_version'] = e_ident['EI_ABIVERSION']
        dic['Data'] = describe_ei_data(e_ident['EI_DATA'])
        dic['Class'] = describe_ei_class(e_ident['EI_CLASS'])
    
        return dic


    def sections(self):
        dic = {}
    
        for section in self.elf.iter_sections():
            dic[section.name] = {}
            dic[section.name]['Addr'] = section['sh_addr']
            dic[section.name]['Size'] = section['sh_size']
            dic[section.name]['Type'] = section['sh_type']
            dic[section.name]['Flags'] = describe_sh_flags(section['sh_flags'])
    
        return dic

    def symbols(self):
        dic = {}
        dict = {}
        returnValue = {}
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            dict[section.name] = {}
            for cnt, symbol in enumerate(section.iter_symbols()):
                dic[cnt] = {}
                dic[cnt]['Value'] = hex(symbol['st_value'])
                dic[cnt]['Size'] = hex(symbol['st_size'])
                dic[cnt]['Type'] = symbol['st_info']['type']
                dic[cnt]['Name'] = symbol.name
                dic[cnt]['Bind'] = symbol['st_info']['bind']
                dic[cnt]['Ndx'] = symbol['st_shndx']

            dict[section.name] = dic
        #Imported Functions
        returnValue['Imported Functions'] = []
        returnValue['Exported Functions'] = []
        for i in dict:
            for j in dict[i]:
                if(dict[i][j]['Ndx']== 'SHN_UNDEF' and dict[i][j]['Bind'] != 'STB_LOCAL'):
                    returnValue['Imported Functions'].append({'Name':dict[i][j]['Name'], 'Type':dict[i][j]['Type'].split('_')[1]})
                if((dict[i][j]['Type'] == 'STT_FUNC' or dict[i][j]['Type'] == 'STT_OBJECT') and dict[i][j]['Bind'] != 'STB_LOCAL'):
                    returnValue['Exported Functions'].append({'Name':dict[i][j]['Name'], 'Type':dict[i][j]['Type'].split('_')[1]})
    
        return returnValue
    


    def dynamic(self):
        dic = {}
        for section in self.elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            dic[section.name] = []
            for tag in section.iter_tags():
                if tag.entry.d_tag != "DT_NEEDED":
                    continue
                dic[section.name].append(tag.needed)
    
        return dic

    def segments(self):
        dic = {}
        interpreter = ''
        count = 0
        for segment in self.elf.iter_segments():
            dic[count] = {}
            if(segment['p_type'] == 'PT_INTERP'):
                interpreter = segment.get_interp_name()
                dic['Interpreter'] = interpreter
            dic[count]['Type'] = segment['p_type']
            dic[count]['VirtualAddr'] = hex(segment['p_vaddr'])
            dic[count]['FileSize'] = hex(segment['p_filesz'])
            dic[count]['MemSize'] = hex(segment['p_memsz'])
            dic[count]['Flags'] = describe_p_flags(segment['p_flags'])

            count = count +1
        return dic

    def section_segment_mapping(self):
        segment_list = []
        for segment in self.elf.iter_segments():
            dic = {}
            dic[segment['p_type']] = []
            for section in self.elf.iter_sections():
                if(segment.section_in_segment(section)):
                    dic[segment['p_type']].append(section.name)
            segment_list.append(dic)
        return segment_list


'''
with open(sys.argv[1], 'rb') as f:
    data = f.read()

final_data = {}
elf = ELFFile(BytesIO(data))
final_data['Header'] = headers(elf)
final_data['Segments'] = segments(elf)
final_data['Sections'] = sections(elf)
final_data['Symbols'] = symbols(elf)
final_data['Shared Libaries'] = dynamic(elf)
final_data['Section Segment Mapping'] = section_segment_mapping(elf)

#print(final_data)

out_filename = sys.argv[1].split('.')[0]+'.json'
with open(out_filename, 'w') as f:
    json.dump(final_data, f)
'''

