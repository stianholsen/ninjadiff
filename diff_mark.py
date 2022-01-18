#!/usr/bin/env python3

# Copyright 2019 River Loop Security LLC, All Rights Reserved
# Author Rylan O'Connell

import binaryninja as binja

import math
from typing import Tuple, List, Dict

from . import functionTypes, instructionComparator

Binary_View = binja.binaryview.BinaryView


class BackgroundDiffer2(binja.BackgroundTaskThread):
    def __init__(self, src_bv: Binary_View, dst_bv: Binary_View):
        binja.BackgroundTaskThread.__init__(self, 'Diffing...', True)
        self.src_bv = src_bv
        self.dst_bv = dst_bv
        self.address_map = AddressMap()
        self.similar_functions = []

    def run(self):
        # ensure both views have finished processing before we continue
        #self.src_bv.update_analysis_and_wait()
        self.dst_bv.update_analysis_and_wait()

        print('started diffing...')
        diff_tt = self.src_bv.create_tag_type('Difference', '🚫')
        new_function_tt = self.src_bv.create_tag_type('New function', '➕')

        dst_functions = self.ingest(self.dst_bv)
        src_functions = self.ingest(self.src_bv)

        # attempt to match source functions to destination functions
        for dst_function in dst_functions:
            min_pairing, distance = self.get_min_pair(dst_function, src_functions)
            if min_pairing is not None:
                print('diffing {} against {}'.format(dst_function.source_function.name, min_pairing.source_function.name))
                self.similar_functions.append((dst_function.address, min_pairing.address, distance))
            # if pairing failed (ie. no similar functions in the dest binary), assume it is not present in src
            if min_pairing is None:
                continue

            # attempt to build a mapping between addresses in the source and destination binaries
            self.address_map.add_mapping(src_addr=dst_function.address, dst_addr=min_pairing.address)
            src_instrs = list(dst_function.source_function.hlil.instructions)
            dst_instrs = list(min_pairing.source_function.hlil.instructions)
            for instr_index in range(min(len(src_instrs), len(dst_instrs))):
                src_instr = src_instrs[instr_index]
                dst_instr = dst_instrs[instr_index]

                if instructionComparator.compare_instructions(src_instr, dst_instr):
            #        dst_function.source_function.set_user_instr_highlight(
            #            src_instr.address,
            #            binja.highlight.HighlightStandardColor.GreenHighlightColor
            #        )

                    min_pairing.source_function.set_user_instr_highlight(
                        dst_instr.address,
                        binja.highlight.HighlightStandardColor.GreenHighlightColor
                    )

        print('finished diffing')

    def get_min_pair(self, function: functionTypes.FunctionWrapper, pairings: List[functionTypes.FunctionWrapper]) -> Tuple[functionTypes.FunctionWrapper, float]:
        min_distance = math.inf
        min_pairing = None

        for pairing in pairings:
            distance = function.distance(pairing)
            # only accept pairings "close" to the original (accounting for function size)
            if (distance < min_distance) and \
                    (distance < 0.40 * (function.number_of_basic_blocks() + .1 * function.number_of_edges())):
                min_distance = distance
                min_pairing = pairing

        return min_pairing, min_distance

    def ingest(self, bv: Binary_View) -> List[functionTypes.FunctionWrapper]:
        functions = []
        for function in bv.functions:
            # ignore small functions to minimize false positives
            if len(function.basic_blocks) < 5:
                continue

            function_with_metadata = functionTypes.FunctionWrapper(function)
            functions.append(function_with_metadata)

        return functions

    def join(self):
        return self.similar_functions


class AddressMap:
    def __init__(self):
        self.src_to_dst = {}
        self.dst_to_src = {}

    def add_mapping(self, src_addr, dst_addr):
        self.src_to_dst[src_addr] = dst_addr
        self.dst_to_src[dst_addr] = src_addr

    def src2dst(self, src_addr):
        try:
            return self.src_to_dst[src_addr]
        except KeyError:
            return None

    def dst2src(self, dst_addr):
        try:
            return self.dst_to_src[dst_addr]
        except KeyError:
            return None
