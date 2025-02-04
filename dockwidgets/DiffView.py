from PySide2.QtCore import Qt, QTimer
from PySide2.QtWidgets import QApplication, QVBoxLayout, QWidget, QSplitter, QLabel

import re
import os
import time

import binaryninjaui
from binaryninja import BinaryView, core_version, interaction, BinaryViewType, plugin, Function
from binaryninjaui import View, ViewType, UIAction, LinearView, ViewFrame, TokenizedTextView, DockHandler

from .. import diff

(major, minor, buildid) = re.match(r'^(\d+)\.(\d+)\.?(\d+)?', core_version()).groups()
major = int(major)
minor = int(minor)
buildid = int(buildid) if buildid is not None else 0xffffffff


class DiffView(QWidget, View):

	def _analysis(self):
		# open secondary file and begin non-blocking analysis
		if self.dst_bv is None:
			raise Exception('invalid file path')

		self.dst_bv.update_analysis()

		# begin diffing process in background thread
		differ = diff.BackgroundDiffer(self.src_bv, self.dst_bv)
		differ.start()
		self.address_map = differ.address_map
		while differ.finished == False:
			print("waiting for background task to complete")
			time.sleep(2)
		print("background task completed")

	def _analysis_and_view(self, parent):
		# open secondary file and begin non-blocking analysis
		if self.dst_bv is None:
			raise Exception('invalid file path')

		self.dst_bv.update_analysis()

		# begin diffing process in background thread
		differ = diff.BackgroundDiffer(self.src_bv, self.dst_bv)
		differ.start()
		self.address_map = differ.address_map

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
		while differ.finished == False:
			print("waiting for background task to complete")
			time.sleep(2)
		print("background task completed")

	def __init__(self, parent, data):
		if not type(data) == BinaryView:
			raise Exception('expected widget data to be a BinaryView')

		self.src_bv: BinaryView = data
		choice = interaction.get_int_input("Promt>", "1 for standard diffing, 2 for folder")
		if choice == 2:
			foldername = interaction.get_directory_name_input('Folder for Diffing:').decode('utf-8')
			print(foldername)
			for filename in os.listdir(foldername)[1:3]:
				self.dst_bv: BinaryView = BinaryViewType.get_view_of_file(os.path.join(foldername, filename), update_analysis=False)
				print("Analysing: ", self.src_bv.file.filename, " and ", self.dst_bv.file.filename)
				if filename == os.listdir(foldername)[1]:
					self._analysis_and_view(parent)
				else:
					self._analysis()
				self.src_bv = self.dst_bv
		else:
			fname = interaction.get_open_filename_input('File to Diff:').decode('utf-8')
			print('opening {}...'.format(fname))
			self.dst_bv: BinaryView = BinaryViewType.get_view_of_file(fname, update_analysis=False)
			print(self.dst_bv.file.filename)
			self._analysis_and_view(parent)

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

