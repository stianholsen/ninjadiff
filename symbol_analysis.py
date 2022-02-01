import re
import os
import time
from os import listdir
from os.path import isfile, join, isdir
import json

import binaryninja as binja

import binaryninjaui
from binaryninja import BinaryView, core_version, interaction, BinaryViewType, plugin, Function
from binaryninjaui import View, ViewType, UIAction, LinearView, ViewFrame, TokenizedTextView, DockHandler
from binaryninja.interaction import DirectoryNameField, LabelField, OpenFileNameField
from binaryninja.enums import SymbolType

from . import diff, diff_remove, diff_mark, db

class SymbolAnalysis(binja.BackgroundTaskThread):
    def __init__(self):
        binja.BackgroundTaskThread.__init__(self, 'Analysing symbols...', True)
        linux_behavior = open('/Users/stianholsen2/Library/Application Support/Binary Ninja/plugins/ninjadiff/linux-behavior.json', 'r')
        self.linux_behavior = json.loads(linux_behavior.read())
        self.symbol_by_time = []
        self.symbol_by_malware = []

    def run(self):
        self.bv.update_analysis_and_wait()
        sections = self.bv.sections
        self.symbol_arr = {}
        for section in sections:
            for i in self.bv.get_strings(self.bv.sections[section].start, self.bv.sections[section].end-self.bv.sections[section].start):
                if re.search(self.linux_behavior['Subsystems Initialization']['regex'], i.value):
                    if 'Subsystems Initialization' in self.symbol_arr and i.value not in self.symbol_arr['Subsystems Initialization']:
                        self.symbol_arr['Subsystems Initialization'].append(i.value)
                    elif 'Subsystems Initialization' not in self.symbol_arr:
                        self.symbol_arr['Subsystems Initialization'] = [i.value]
                if re.search(self.linux_behavior['Time-based Execution']['regex'], i.value):
                    if 'Time-based Execution' in self.symbol_arr and i.value not in self.symbol_arr['Time-based Execution']:
                        self.symbol_arr['Time-based Execution'].append(i.value)
                    elif 'Time-based Execution' not in self.symbol_arr:
                        self.symbol_arr['Time-based Execution'] = [i.value]
                if re.search(self.linux_behavior['Sandbox Detection']['regex'], i.value):
                    if 'Sandbox Detection' in self.symbol_arr and i.value not in self.symbol_arr['Sandbox Detection']:
                        self.symbol_arr['Sandbox Detection'].append(i.value)
                    elif 'Sandbox Detection' not in self.symbol_arr:
                        self.symbol_arr['Sandbox Detection'] = [i.value]
                if re.search(self.linux_behavior['Anti-Debugging']['regex'], i.value):
                    if 'Anti-Debugging' in self.symbol_arr and i.value not in self.symbol_arr['Anti-Debugging']:
                        self.symbol_arr['Anti-Debugging'].append(i.value)
                    elif 'Anti-Debugging' in self.symbol_arr:
                        self.symbol_arr['Anti-Debugging'] = [i.value]
                if re.search(self.linux_behavior['Privilege Escalation']['regex'], i.value):
                    if 'Privilege Escalation' in self.symbol_arr and i.value not in self.symbol_arr['Privilege Escalation']:
                        self.symbol_arr['Privilege Escalation'].append(i.value)
                    elif 'Privilege Escalation' not in self.symbol_arr:
                        self.symbol_arr['Privilege Escalation'] = [i.value]
                if re.search(self.linux_behavior['Process Renaming and Termination']['regex'], i.value):
                    if 'Process Renaming and Termination' in self.symbol_arr and i.value not in self.symbol_arr['Process Renaming and Termination']:
                        self.symbol_arr['Process Renaming and Termination'].append(i.value)
                    elif 'Process Renaming and Termination' not in self.symbol_arr:
                        self.symbol_arr['Process Renaming and Termination'] = [i.value]
                if re.search("(ls -ld|^wget|busybox|dpkgd|.*\.elf|( |^)chmod |( |^)cp |( |^)rm |( |^)cat |/proc/mounts|/bin/echo|dvrHelper|mkdir|execute|kill|ftp|http)", i.value):
                    if 'File Infection and Replacement' in self.symbol_arr and i.value not in self.symbol_arr['File Infection and Replacement']:
                        self.symbol_arr['File Infection and Replacement'].append(i.value)
                    elif 'File Infection and Replacement' not in self.symbol_arr:
                        self.symbol_arr['File Infection and Replacement'] = [i.value]
                if re.search(self.linux_behavior['Network Information']['regex'], i.value):
                    if 'Network Information' in self.symbol_arr and i.value not in self.symbol_arr['Network Information']:
                        self.symbol_arr['Network Information'].append(i.value)
                    elif 'Network Information' not in self.symbol_arr:
                        self.symbol_arr['Network Information'] = [i.value]
                if re.search(self.linux_behavior['Process Injection']['regex'], i.value):
                    if 'Process Injection' in self.symbol_arr and i.value not in self.symbol_arr['Process Injection']:
                        self.symbol_arr['Process Injection'].append(i.value)
                    elif 'Process Injection' not in self.symbol_arr:
                        self.symbol_arr['Process Injection'] = [i.value]
                if re.search(self.linux_behavior['Stalling Code']['regex'], i.value):
                    if 'Stalling Code' in self.symbol_arr and i.value not in self.symbol_arr['Stalling Code']:
                        self.symbol_arr['Stalling Code'].append(i.value)
                    elif "Stalling Code" not in self.symbol_arr:
                        self.symbol_arr['Stalling Code'] = [i.value]           
                if re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", i.value):
                    if 'IPs' in self.symbol_arr and i.value not in self.symbol_arr['IPs']:
                        self.symbol_arr['IPs'].append(i.value)
                    elif 'IPs' not in self.symbol_arr:
                        self.symbol_arr['IPs'] = [i.value]                   
            for i in self.bv.get_symbols(self.bv.sections[section].start, self.bv.sections[section].end-self.bv.sections[section].start):
                if re.search(\
                    "(DNS|master|DDoS|telnet|SSH|xmas|sp(\w{1,2})f|bot|wget|fl(\w{1,2})d|STD|suicide|infectFunction|reverse|shell|busybox|infectedFunnction|exploit|backdoor|nanosleep|_kill|_setup_connection|attack_method|attack_|greeth|greip|server|fake)"\
                        , i.name, re.IGNORECASE) and re.search("^__*", i.name) == None and i.type == SymbolType.FunctionSymbol:                   
                    if 'Functions' in self.symbol_arr:
                        self.symbol_arr['Functions'].append(i.name)
                    else:
                        self.symbol_arr['Functions'] = [i.name]
                if re.search("_gdb_", i.name, re.IGNORECASE) and re.search("^__*", i.name) == None and i.type == SymbolType.FunctionSymbol:
                    if 'Anti-Debugging' in self.symbol_arr and i.name not in self.symbol_arr['Anti-Debugging']:
                        self.symbol_arr['Anti-Debugging'].append(i.name)
                    elif 'Anti-Debugging' in self.symbol_arr:
                        self.symbol_arr['Anti-Debugging'] = [i.name]                     

    def set_file_and_type(self, bv, malware_type):
        self.bv = bv
        self.malware_type = malware_type
    
    def join_symbols(self):
        return (self.symbol_by_time, self.symbol_by_malware)
    
    def join_symbol_dict(self):
        return self.symbol_arr
