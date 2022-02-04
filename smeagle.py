#!/usr/bin/env python

# Smeagle in Python using angr

import angr
from angr.knowledge_plugins.cfg import CFGNode, CFGModel, MemoryDataSort
from angr.sim_variable import SimMemoryVariable
from cle import SymbolType

import tempfile
import shutil
import argparse
import re
import json
import sys
import os


# 1. Build a CFG (project.analyses.CFGFast()). This will recover functions and associate names from the binary's debug symbols with them.

# 2. Run the calling convention analysis (project.analyses.CallingConventionAnalysis()), then variable recovery (project.analyses.VariableRecoveryFast()), then type inference (project.analyses.Typehoon()).

# 3. The calling convention you get back from the first part of 2 will be a SimCC. This (when provided with a function prototype, which CCA should also give you) gives you very detailed information about how a function's parameters should be laid out in registers and memory.

# 4. Unclear what you're asking for. Various analyses listed above take callsites into consideration during their analysis, and you can retrieve all callsites of a function by asking for its predecessors in the interprocedural CFG, but I don't know what it means to "parse" a callsite.

# 5. CLE will automatically parse any debug information related to exception handling (for ELF tiles only) into project.loader.main_object.exception_handlings. CFGFast will by default use these to add special "exception" edges to the graph, though I'm not super clear on what information this gives you.


def get_parser():
    parser = argparse.ArgumentParser(
        description="Smeagle Python",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("binary", help="Binary to analyze.")
    return parser


class Analyzer:
    def __init__(self, path, flavor="pseudocode", auto_load_libs=False):
        """
        Arguments:
        
        path (str): the path to the binary to parse
        flavor (str): I'm not sure but this is what I see in examples
        auto_load_libs (bool): auto load libraries
        """
        self.cfg = None
        if not os.path.exists(path):
            sys.exit("%s does not exist!" % path)

        # If we set auto_load_libs to true we also parse all linked libs!
        # Note that if we want to do this, we can look at func.owner.symbol
        self.proj = angr.Project(path, load_options={"auto_load_libs": auto_load_libs})
        self.data = {"library": os.path.abspath(path), "locations": []}

        # TODO self.proj.kb.callgraph is networkx, we can probably plot it

    def run(self):
        """
        Run the analyzer to build a control flow graph (CFG). This will recover
        functions and associate names from the binary debug symbols
        """
        self.cfg = self.proj.analyses.CFGFast(objects=self.proj.loader.all_objects)

        # Parse functions and variables from functions into data
        self._set_global_variables()
        self._parse_functions()

    def _set_global_variables(self):
        global_variables = self.cfg.kb.variables["global"]
        for symbol in self.proj.loader.main_object.symbols:
            if symbol.type == SymbolType.TYPE_OBJECT:

                # TODO add variables here?
                global_variables.set_variable(
                    "global",
                    symbol.rebased_addr,
                    SimMemoryVariable(symbol.rebased_addr, 1, name=symbol.name),
                )


    def _parse_functions(self):
        """
        Iterate through the knowledge base functions to derive metadata!
        """
        if not self.cfg:
            sys.exit("You should not run this function directly - use run.")
        print("Parsing functions...")

        # prepare a state (or use last one)
        state = angr.SimState(arch=self.proj.arch)

        for key, func in self.cfg.kb.functions.items():

            # In examples I've seen these skipped
            if func.is_simprocedure:
                continue

            # Only parse those owned by our library
            if func.symbol and self.data['library'] != func.symbol.owner.binary:
                continue

            # This looks like it matches func.symbol.name
            # We can do additional filter here based on symbol params if needed
            entry = {"name": func.name, "size": func.size}

            # Run the calling convention analysis (this has arch and registers)
            # We get back a SimCC to give us detailed information about how a function's parameters should be laid out in registers and memory.
            convention = self.proj.analyses.CallingConvention(
                func, analyze_callsites=True
            )

            if not convention.cc:
                print('NO CC')
                import IPython
                IPython.embed()
                continue

            # Then variable recovery
            vr = self.proj.analyses.VariableRecoveryFast(func)

            # And type inference
            types = self.proj.analyses.Typehoon(vr.type_constraints)

            # Some calls don't have prototype so we skip?
            if not convention.prototype:
                self.data['locations'].append(entry)
                continue

            entry['parameters'] = []
            for arg_info in convention.cc.get_arg_info(
                state=state, prototype=convention.prototype
            ):
                typ = arg_info[0]
                register = arg_info[2]
                typ = typ.with_arch(convention.cc.arch)
                entry["parameters"].append(
                    {
                        "type": typ.c_repr(),
                        "size": typ.size,
                        "location": register.reg_name,
                    }
                )

            # TODO add parser based on types

            # If we have a return type, add it
            if convention.prototype.returnty:
                returnt = convention.prototype.returnty.with_arch(self.proj.arch)
                entry["parameters"].append(
                    {"type": returnt.c_repr(), "size": returnt.size, "location": "rax"}
                )

            # TODO some method to determine we've seen something?
            self.data["locations"].append(entry)


def main():

    parser = get_parser()
    args, extra = parser.parse_known_args()
    a = Analyzer(args.binary)
    a.run()
    print(json.dumps(a.data, indent=4))


if __name__ == "__main__":
    main()
