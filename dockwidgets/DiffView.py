from PySide2.QtCore import Qt, QTimer
from PySide2.QtWidgets import QApplication, QVBoxLayout, QWidget, QSplitter, QLabel

import re
import os
import time
from os import listdir
from os.path import isfile, join, isdir

import binaryninjaui
from binaryninja import BinaryView, core_version, interaction, BinaryViewType, plugin, Function
from binaryninjaui import View, ViewType, UIAction, LinearView, ViewFrame, TokenizedTextView, DockHandler
from binaryninja.interaction import DirectoryNameField, LabelField, OpenFileNameField

from .. import diff, diff_remove, diff_mark, db, symbol_analysis

(major, minor, buildid) = re.match(r'^(\d+)\.(\d+)\.?(\d+)?', core_version()).groups()
major = int(major)
minor = int(minor)
buildid = int(buildid) if buildid is not None else 0xffffffff

class DiffView(QWidget, View):

	def __init__(self, parent, data):
		if not type(data) == BinaryView:
			raise Exception('expected widget data to be a BinaryView')

		self.src_bv: BinaryView = data
		dbconnection = db.DBconnector((self.src_bv.file.filename.split('/')[-1]).split('_')[1])
		folder_label = LabelField("Select folders to diff multiple files")
		malware_type_folder = DirectoryNameField("Folder containing malware type")
		malware_time_folder = DirectoryNameField("Folder for malware comparison")
		file_label = LabelField("Select file to diff 1 on 1")
		open_file = OpenFileNameField("Open file")
		interaction.get_form_input(["Select folders or a file", None,folder_label, malware_type_folder, malware_time_folder, file_label, open_file], "The options")

		QWidget.__init__(self, parent)
		View.__init__(self)
		self.similar_source_functions = []
		replace = False
		if open_file.result != '':
			self.dst_bv: BinaryView = BinaryViewType.get_view_of_file(open_file.result, update_analysis=False)	
			print("Analysing: ", self.src_bv.file.filename, " and ", self.dst_bv.file.filename)
			self._analysis_and_ui(replace, 1)
		else:
			if malware_type_folder.result != '':
				for filename in os.listdir(malware_type_folder.result)[0:5]:
					print("Functions before removing: ", len(self.src_bv.functions))
					file_size = os.path.getsize(os.path.join(malware_type_folder.result, filename))
					if filename != self.src_bv.file.filename and int(file_size)/1000 < 400:
						self.dst_bv: BinaryView = BinaryViewType.get_view_of_file(os.path.join(malware_type_folder.result, filename), update_analysis=False)
						print("Analysing removing: ", self.src_bv.file.filename, " and ", self.dst_bv.file.filename)
						self._analysis_and_ui(replace, 2)
						replace = True
						print("Functions after removing: ", len(self.src_bv.functions))

			if malware_time_folder.result != '':
				count = 0
				malware_time_files = []
				malware_time_files = [join(malware_time_folder.result, f) for f in listdir(malware_time_folder.result) if isfile(join(malware_time_folder.result, f)) and 'VirusShare' in f]
				malware_time_folders = [f for f in listdir(malware_time_folder.result) if isdir(join(malware_time_folder.result, f))]
				for folder in malware_time_folders:
					if join(malware_time_folder.result, folder) != malware_type_folder.result:
						files = [join(malware_time_folder.result, folder, f) for f in listdir(join(malware_time_folder.result, folder)) if isfile(join(malware_time_folder.result, folder, f)) and 'VirusShare' in f]
						malware_time_files.extend(files)

				for filename in malware_time_files[0:]:
					file_size = os.path.getsize(filename)
					if filename.split('/')[-1] != self.src_bv.file.filename and dbconnection.search_by_md5(filename.split('/')[-1].split('_')[1]) and int(file_size)/1000 < 400 :
						self.dst_bv: BinaryView = BinaryViewType.get_view_of_file(filename, update_analysis=False)
						print("Analysing marking: ", self.src_bv.file.filename, " and ", self.dst_bv.file.filename)
						self._analysis_and_ui(replace, 3)
						replace = True
						count = count + 1
					if count == 40:
						break
			
			for function in self.similar_source_functions:
				print("similar functions: {}, {}, {}".format(hex(function[0]), hex(function[1]), function[2]))

	def _analysis_and_ui(self, new, diff_type):
		if self.dst_bv is None:
			raise Execption('invalid file path')
		self.dst_bv.update_analysis()

		if diff_type == 1:
			# begin diffing process in background thread
			differ = diff.BackgroundDiffer(self.src_bv, self.dst_bv)
			differ.start()
		elif diff_type == 2:
			# begin diffing process in background thread
			differ = diff_remove.BackgroundDiffer1(self.src_bv, self.dst_bv)
			differ.start()
		elif diff_type == 3:
			# begin diffing process in background thread
			differ = diff_mark.BackgroundDiffer2(self.src_bv, self.dst_bv)
			differ.start()
		else:
			return
		self.address_map = differ.address_map

		self.setupView(self)

		self.current_offset = 0

		self.splitter = QSplitter(Qt.Orientation.Horizontal, self)

		frame = ViewFrame.viewFrameForWidget(self)
		self.dst_editor = LinearView(self.dst_bv, frame)
		self.dst_editor.setAccessibleName('Destination Editor')
		self.src_editor = LinearView(self.src_bv, frame)
		self.src_editor.setAccessibleName('Source Editor')

		# sync location between src and dst panes
		self.sync = True

		if new == False:
			self.binary_text = TokenizedTextView(self, self.src_bv)
			self.is_raw_disassembly = False
			self.raw_address = 0

		self.is_navigating_history = False
		self.memory_history_addr = 0

		small_font = QApplication.font()
		small_font.setPointSize(11)

		if new == False:
			self.splitter.addWidget(self.src_editor)
			self.splitter.addWidget(self.dst_editor)
		if new == True:
			self.splitter.replaceWidget(2, self.dst_editor)
	
		# Equally sized
		self.splitter.setSizes([0x7fffffff, 0x7fffffff])

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		layout.addWidget(self.splitter, 100)
		self.setLayout(layout)

		self.needs_update = True
		self.update_timer = QTimer(self)
		self.update_timer.setInterval(200)
		self.update_timer.setSingleShot(False)
		self.update_timer.timeout.connect(lambda: self.updateTimerEvent())
		while differ.finished == False:
			print("Waiting for background task to finish")
			time.sleep(8)

		if diff_type == 3:
			functions = differ.join()
			for function in functions:
				if function not in self.similar_source_functions:
					self.similar_source_functions.append(function)

		print("finish background task")
		#QWidget.close()

	def goToReference(self, func: Function, source: int, target: int):
		return self.navigate(func.start)

	def navigateToFunction(self, func, offset):
		return self.navigate(offset)

	def navigate(self, addr):
		function = self.src_bv.get_function_at(addr)
		function_addr = None if function is None else function.start
		if function_addr is not None:
			status = self.src_editor.navigate(function_addr)

			dst_addr = self.address_map.src2dst(function_addr)
			if dst_addr is not None:
				self.dst_editor.navigate(dst_addr)
			return status

		return False


	def getData(self):
		return self.src_bv

	def getFont(self):
		return binaryninjaui.getMonospaceFont(self)

	def getCurrentOffset(self):
		offset = self.src_editor.getCurrentOffset()
		return offset

	def getSelectionOffsets(self):
		if not self.is_raw_disassembly:
			return self.src_editor.getSelectionOffsets()
		return (self.raw_address, self.raw_address)

	def getCurrentArchitecture(self):
		if not self.is_raw_disassembly:
			return self.src_editor.getCurrentArchitecture()
		return None

	def getCurrentLowLevelILFunction(self):
		if not self.is_raw_disassembly:
			return self.src_editor.getCurrentLowLevelILFunction()
		return None

	def getCurrentMediumLevelILFunction(self):
		if not self.is_raw_disassembly:
			return self.src_editor.getCurrentMediumLevelILFunction()
		return None

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True


class DiffViewType(ViewType):
	# executed at plugin load time from from ui.py ViewType.registerViewType()
	def __init__(self):
		super(DiffViewType, self).__init__("Diff", "Diff")

	def getPriority(self, data, filename):
		return 1

	# executed when user clicks "Debugger" from dropdown with binary views
	def create(self, data, view_frame):
		return DiffView(view_frame, data)

