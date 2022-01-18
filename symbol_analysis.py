import re
import os
import time
from os import listdir
from os.path import isfile, join, isdir
import json

import binaryninjaui
from binaryninja import BinaryView, core_version, interaction, BinaryViewType, plugin, Function
from binaryninjaui import View, ViewType, UIAction, LinearView, ViewFrame, TokenizedTextView, DockHandler
from binaryninja.interaction import DirectoryNameField, LabelField, OpenFileNameField

from . import diff, diff_remove, diff_mark, db

class SymbolAnalysis:
    def __init__(self, bv):
        self.bv = bv
        linux_behavior = open('/Users/stianholsen2/Library/Application Support/Binary Ninja/plugins/ninjadiff/linux-behavior.json', 'r')
        self.linux_behavior = json.loads(linux_behavior.read())

    def symbols(self):
        sections = bv.sections
        for section in sections:
	        for i in bv.get_strings(bv.sections[section].start, bv.sections[section].start-bv.sections[section].end):
		        if i.value in self.linux_behavior['Subsystems Initialization'] or i.value in self.linux_behavior['Time-based Execution'] or i.value in self.linux_behavior['File Systems']:
		    	    print(i)
