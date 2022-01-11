from PySide2.QtCore import Qt, QTimer
from PySide2.QtWidgets import QApplication, QVBoxLayout, QWidget, QSplitter, QLabel

import re
import os
import time

import binaryninjaui
from binaryninja import BinaryView, core_version, interaction, BinaryViewType, plugin, Function
from binaryninjaui import View, ViewType, UIAction, LinearView, ViewFrame, TokenizedTextView, DockHandler
from binaryninja.interaction import DirectoryNameField

from .. import diff, diff_remove, diff_mark, db

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
		choice = interaction.get_int_input("Promt>", "1 for standard diffing, 2 for folder")
		if choice == 2:
			malware_type_folder = DirectoryNameField("Folder containing malware type")
			malware_time_folder = DirectoryNameField("Folder for malware comparison")
			interaction.get_form_input(["Get Data", None, malware_type_folder, malware_time_folder], "The options")
			print(malware_type_folder.result, malware_time_folder.result)
			#self.src_bv.update_analysis()
			#print('Source updated')
			print("Functions before: ", len(self.src_bv.functions))
			for filename in os.listdir(malware_type_folder.result)[0:0]:
				file_size = os.path.getsize(os.path.join(malware_type_folder.result, filename))
				if filename != self.src_bv.file.filename and int(file_size)/1000 < 300:
					self.dst_bv: BinaryView = BinaryViewType.get_view_of_file(os.path.join(malware_type_folder.result, filename), update_analysis=False)
					print("Analysing: ", self.src_bv.file.filename, " and ", self.dst_bv.file.filename)
					self._analysis()
					time.sleep(3)
			print("Functions after: ", len(self.src_bv.functions))
			count = 0
			for filename in os.listdir(malware_time_folder.result)[0:10]:
				file_size = os.path.getsize(os.path.join(malware_time_folder.result, filename))
				if filename != self.src_bv.file.filename and int(file_size)/1000 < 200 and dbconnection.search_by_md5(filename.split('_')[1]):
					self.dst_bv: BinaryView = BinaryViewType.get_view_of_file(os.path.join(malware_time_folder.result, filename), update_analysis=False)
					print("Analysing: ", self.src_bv.file.filename, " and ", self.dst_bv.file.filename)
					self._analysis_over_time()
					time.sleep(3)
					count = count + 1
				if count == 10:
					break
		else:
			fname = interaction.get_open_filename_input('File to Diff:').decode('utf-8')
			print('opening {}...'.format(fname))
			self.dst_bv: BinaryView = BinaryViewType.get_view_of_file(fname, update_analysis=False)
			print(self.dst_bv.file.filename)
			self._analysis_and_ui(parent)

	def _analysis(self):
		# open secondary file and begin non-blocking analysis
		if self.dst_bv is None:
			raise Exception('invalid file path')

		# begin diffing process in background thread
		differ = diff_remove.BackgroundDiffer(self.src_bv, self.dst_bv)
		differ.start()
		self.address_map = differ.address_map
		print(self.address_map)
		while differ.finished == False:
			print("waiting for background task to complete")
			time.sleep(8)
		print("background task completed")

	def _analysis_over_time(self):
		# open secondary file and begin non-blocking analysis
		if self.dst_bv is None:
			raise Exception('invalid file path')

		# begin diffing process in background thread
		differ2 = diff_mark.BackgroundDiffer2(self.src_bv, self.dst_bv)
		differ2.start()
		self.address_map = differ2.address_map
		print(self.address_map)
		while differ2.finished == False:
			print("waiting for background task to complete")
			time.sleep(8)
		print("background task completed")

	def _analysis_and_ui(self, parent):
		if self.dst_bv is None:
			raise Execption('invalid file path')
		self.dst_bv.update_analysis()

		# begin diffing process in background thread
		differ3 = diff.BackgroundDiffer(self.src_bv, self.dst_bv)
		differ3.start()
		self.address_map = differ3.address_map

		QWidget.__init__(self, parent)
		View.__init__(self)

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

		self.binary_text = TokenizedTextView(self, self.src_bv)
		self.is_raw_disassembly = False
		self.raw_address = 0

		self.is_navigating_history = False
		self.memory_history_addr = 0

		small_font = QApplication.font()
		small_font.setPointSize(11)

		self.splitter.addWidget(self.src_editor)
		self.splitter.addWidget(self.dst_editor)

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

