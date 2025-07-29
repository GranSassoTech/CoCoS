#!/usr/bin/env python3
VERSION = 'CoCoS-0.1-2025.07.25'

""" CoCoS - Continuous Compliance Service
	File analysis script
	
Author:
	Emerson Sales

Assumptions:
	- We are relying on the fact that CoCos is installed in the git root. 
	  This means that all analyzed files start with ../ 
	  and thus, if we want to retrieve a file path, we remove the first three characters of the input name
	- Programs do not have pointer aliasing on functions. 
	  In other words, whenever a function is passed as a pointer, there exists a function definition with the same name.
	- Whenever a function is passed as argument to another function (in the form f(g)), we consider the latter calls the former
	  (f -> g in the function call graph)
	- Type qualifiers, type modifiers and types are treated equally when it comes to function signature change
	  (e.g. although const doesn't change the type itself, if added in a new version of the code it will be flagged as a signature change.
	   The same applies to modifiers such as short and, of course, to actual type changes such as from int to float)
	
ToDos:
	- Instead of saving old version on builder, create two different builders
	- messages with possible plural (e.g. caller(s)) could instead be checked if it is singular or not
	- General refactoring (many parts of the code can be converted into functions, 
	  specially the ones that repeat twice with different parameters)
"""
import argparse
import ast
from collections import defaultdict, deque
import os
import pprint
import shlex
import subprocess

import pycparser
import pycparser.c_ast
from pycparserext.ext_c_parser import FuncDeclExt, GnuCParser # TODO: check if we really need these, otherwise we can drop pycparserext and use just pycparser
from pycparser.c_ast import NodeVisitor, ID, FuncDef, FuncCall



def save_dict_as_python_file(data, output_path, var_name="file_func_map"):
	"""
	Saves a dictionary in a separated python file
	"""
	existing_data = {}

	if os.path.exists(output_path):
		with open(output_path, 'r') as f:
			content = f.read()
			try:
				parsed = ast.parse(content)
				for node in parsed.body:
					if isinstance(node, ast.Assign):
						for target in node.targets:
							if isinstance(target, ast.Name) and target.id == var_name:
								existing_data = eval(compile(ast.Expression(node.value), filename="<ast>", mode="eval"))
			except Exception as e:
				print(f"Warning: failed to parse existing file: {e}")

	# Merge the new data into the existing dictionary
	for k, v in data.items():
		existing_data.setdefault(k, set()).update(v)

	# Write the merged result back
	with open(output_path, 'w') as f:
		f.write(f"# Auto-generated file with {var_name}\n")
		f.write(f"{var_name} = ")
		pprint.pprint(existing_data, stream=f)


def save_change_log(file, new_tag, changed_map, removed_funcs, new_funcs, sig_changes):
	output_path = "../.cocos_change_log"
	skip_counter = 0
	if file not in changed_map.keys(): 
		changes = "{}"
		skip_counter += 1
	else: changes = changed_map[file]
	if not removed_funcs: 
		removed_funcs = "{}"
		skip_counter += 1
	if not new_funcs: 
		new_funcs = "{}"
		skip_counter += 1
	if not sig_changes: 
		sig_changes = "{}"
		skip_counter += 1
	if skip_counter==4:
		print("no changes in the file, skipping log")
		return
	# print("we're here")
	if os.path.exists(output_path):
		with open(output_path, 'r') as f:
			content = f.read()
		# print("and here")
		with open(output_path, 'w') as f:
			f.write(f"{content}\n")
			# print(f"# {file[3:]} = {str(changes)},{str(removed_funcs)},{str(new_funcs)},{str(sig_changes)}")
			f.write(f"# {file[3:]} = {str(changes)},{str(removed_funcs)},{str(new_funcs)},{str(sig_changes)}")
			
	else:
		with open(output_path, 'w') as f:
			f.write(f"### Auto-generated file for CoCoS analysis -- release {new_tag}\n")
			f.write(f"# {file[3:]} = {str(changes)},{str(removed_funcs)},{str(new_funcs)},{str(sig_changes)}")


def extract_func_params(ast):
	"""
	Returns a dict mapping function names to number of parameters from a pycparser AST.
	"""
	func_param_map = {}

	class FuncDefVisitor(pycparser.c_ast.NodeVisitor):
		def visit_FuncDef(self, node):
			func_name = node.decl.name
			coord = node.decl.coord
			ret_type = node.decl
			while hasattr(ret_type,'type'): 
				# print(" 5555 %s " % (param_type))
				if hasattr(ret_type.type, "names"): 
					ret_type = ret_type.type.names
					break
				ret_type = ret_type.type
			params = None
			if isinstance(node.decl.type.args, pycparser.c_ast.ParamList): # TODO: double check if args position is always the same (might need some error treatment here)
				params = node.decl.type.args.params
			func_param_map[func_name] = (params, coord, ret_type)

	v = FuncDefVisitor()
	v.visit(ast)
	return func_param_map


def ast_equal(node1, node2, ignore_coords=True):
	"""
	Given two AST nodes, check if they are equal (optional: ignore line mapping)
	"""
	if type(node1) != type(node2):
		return False

	if isinstance(node1, pycparser.c_ast.Node):
		for attr in node1.__slots__:
			if ignore_coords and attr == 'coord':
				continue
			val1 = getattr(node1, attr)
			val2 = getattr(node2, attr)
			if not ast_equal(val1, val2, ignore_coords):
				return False
		return True

	elif isinstance(node1, list):
		if len(node1) != len(node2):
			return False
		return all(ast_equal(a, b, ignore_coords) for a, b in zip(node1, node2))

	else:
		return node1 == node2
	

def extract_funcdefs(ast):
	"""
	Extracts all function definitions as a dict: name -> FuncDef node.
	"""
	funcdefs = {}

	class FuncDefVisitor(pycparser.c_ast.NodeVisitor):
		def visit_FuncDef(self, node):
			name = node.decl.name
			funcdefs[name] = node

	FuncDefVisitor().visit(ast)
	return funcdefs


def invert_call_graph(call_graph):
	""" 
	Takes a call graph (caller -> callees) and returns the inverse mapping (callee -> callers)
	"""
	reverse_graph = defaultdict(set)

	for caller, callees in call_graph.items():
		for callee in callees:
			reverse_graph[callee].add(caller)

	return dict(reverse_graph)


# adapted from CSeq
''' Extract linemarker information.

	Examples:
		linemarkerinfo('# 1 "<built-in>" 1')		 -->  (1, '<built-in>', 1)
		linemarkerinfo('# 1 "<stdin>"')			     -->  (1, '<stdin>', -1)
		linemarkerinfo('# 1 "include/pthread.h" 2')  -->  (1, 'include/pthread.h', 2)

   (for a description of linemarkers see:
	https://gcc.gnu.org/onlinedocs/gcc-4.3.6/cpp/Preprocessor-Output.html)

'''
def linemarkerinfo(marker):
	# linemarker format:  # LINENO FILE FLAG
	# (note  FLAG  is not mandatory)
	#
	#print "MARKER: '%s'" % marker

	line = marker

	# 1st field: line number
	line = line[2:]
	marker_lineno = line[:line.find('"')-1]

	if marker_lineno.isdigit(): marker_lineno = int(marker_lineno)
	else: return ('-1', '-1', '-1')

	# 2nd field: source file
	line = line[line.find('"')+1:]
	marker_filename = line[:line.find('"')]

	# 3rd field: flag (optional)
	line = line[line.rfind(' ')+1:]
	if line.isdigit() and int(line) <=4 and int(line) >= 1:	marker_flag = int(line)
	else: marker_flag = -1

	return (marker_lineno, marker_filename, marker_flag)


# from CSeq (core.utils)
''' Loads into an array of rows the content of a file, then returns it.
'''
def printFileRows(filename):
	rows = ''

	myfile = open(filename)
	lines = list(myfile)

	for line in lines:
		rows += line

	return rows


def get_callers(call_graph, roots, max_depth):
	reverse = invert_call_graph(call_graph)
	visited = set()
	queue = deque([(r, 0) for r in roots])
	while queue:
		node, depth = queue.popleft()
		if max_depth!=-1 and depth >= max_depth:
			continue
		for parent in reverse.get(node, []):
			if parent not in visited:
				visited.add(parent)
				queue.append((parent, depth + 1))
	return visited


def get_callees(call_graph, roots, max_depth):
	visited = set()
	queue = deque([(r, 0) for r in roots])
	while queue:
		node, depth = queue.popleft()
		if max_depth!=-1 and depth >= max_depth:
			continue
		for child in call_graph.get(node, []):
			if child not in visited:
				visited.add(child)
				queue.append((child, depth + 1))
	return visited


def save_call_graph_to_dot(call_graph, output_path="callgraph.dot"):
	"""
		Takes a function call graph in a map format and converts into a .dot file
	"""
	with open(output_path, 'w') as f:
		f.write("digraph CallGraph {\n")
		f.write("    node [shape=box];\n")  # optional styling

		for caller, callees in call_graph.items():
			for callee in callees:
				f.write(f'    "{caller}" -> "{callee}";\n')

		f.write("}\n")


class CallGraphBuilder(NodeVisitor):
	inputtooutput = {}		# input lines to output lines
	outputtoinput = {}		# output lines to input lines
	outputtofiles = {}		# output lines to input file names
	call_graph = {}         # function_name -> [callee_name, ...]
	call_nodes = {}         # (caller, callee) -> FuncCall node(s)
	funcdefs_new = {}	    # function_name -> FuncDef node
	funcdefs_old = {}	    # function_name -> FuncDef node
	newvisit = False
	params = set()
	current_func = None
	prev_func = None
	target_lines = set()
	changed_func = set()
	new_funcs = set()
	removed_funcs = set()
	inputfile = ''
	

	def visit_FuncDef(self, node):
		# print("funcdef ")
		func_name = node.decl.name
		if self.newvisit:
			self.funcdefs_new[func_name] = node

			self.prev_func = self.current_func
			self.current_func = func_name
			self.call_graph[func_name] = set()

			self.generic_visit(node)

			self.current_func = self.prev_func
		else:
			self.funcdefs_old[func_name] = node
			self.generic_visit(node)



	def visit_FuncCall(self, node):
		if self.newvisit and isinstance(node.name, pycparser.c_ast.ID):
			callee_name = node.name.name
			args = node.args
			if args and isinstance(args, pycparser.c_ast.ExprList):
				for arg in args.exprs:
					if hasattr(arg, "name") and arg.name in self.call_graph.keys():
						self.call_graph[callee_name].add(arg.name)
			if callee_name in self.call_graph.keys(): self.call_graph[self.current_func].add(callee_name)
			self.call_nodes.setdefault((self.current_func, callee_name), []).append(node)

		self.generic_visit(node)
		
		
	def visit_Decl(self, node, no_type=False):
		if isinstance(node.type, FuncDeclExt) and self.newvisit:
			self.call_graph[node.name] = set()
		self.generic_visit(node)
	
	
	def visit(self, node):
		if self.newvisit and self.target_lines and hasattr(node, "coord"):
			coord = node.coord
			lineout,fileout = self.map_line_to_input_file(coord.line) if coord else (None, None)
			if lineout in self.target_lines and self.inputfile==fileout:
				if self.current_func:
					self.changed_func.add(self.current_func)
					self.target_lines.remove(lineout)
				else:
					print("line " + str(lineout) + " does not refer to actual change")
		return super().visit(node) 

	# adapted from CSeq (core.Merger)
	def preprocess_and_run(self, inputfile, filepath, includepaths, showast=False): # TODO: split this functions in two
		
		includestring = ' -I%s' % os.path.dirname(__file__)+'/include' # include fake headers first

		# TODO: the whole following block is experimental
		includepaths = {str(x.strip()) for x in includepaths.split(",") if x.strip()}
		for include in includepaths:
			includestring += ' -I../%s' % include
		includestring += ' -I../src/lib '
		includestring += ' -I../src/lib/include '
		includestring += ' -I../Include '
		# end block
		
		localincludepath = filepath[:filepath.rfind('/')] if '/' in filepath else ''

		if localincludepath!='': includestring += ' -I%s' % localincludepath
		
		macros = "-D'__attribute__(x)=' -D'__extension__(x)=' -D'__volatile__='"

		# Note: must use gcc
		cmdline = 'gcc %s -nostdinc %s -E -' % (macros,includestring) # hyphen at the end forces input from stdin
		p = subprocess.Popen(shlex.split(cmdline), stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
		stdout, stderr = p.communicate(input=inputfile.encode())

		if stderr:
			print("Preprocessing error:\n", stderr.decode())
			return None
		
		string = stdout.decode()
		input = string.splitlines()

		output = ''			 # clean input (without linemarkers)
		outputlineno = 0		# current output line number (clean, no linemarkers)
		inputlinenooffset = 0   # number of input lines since the last marker

		# coords fetched from the last linemarker
		lastinputfile = ''	  # input file from the last linemarker
		lastinputlineno = 0	 # line number from the last linemarker

		for line in input:
			if line.startswith('# '):
				pass
				inputlinenooffset = -1
				(lastinputlineno,lastinputfile,lastflag) = linemarkerinfo(line)
			else:
				#  correcting line mapping due to preprocessing
				outputlineno += 1
				inputlinenooffset += 1
				self.outputtoinput[outputlineno] = lastinputlineno+inputlinenooffset
				self.outputtofiles[outputlineno] = lastinputfile if lastinputfile!='<stdin>' else filepath
				output += line + '\n'

		self.markedoutput = string
		self.output = output
		self.lastoutputlineno = outputlineno

		parser = GnuCParser()
		ast = parser.parse(self.output)
		if showast: 
			ast.show()
			exit()
		self.visit(ast)
		return self, ast


	''' Returns the coords of the original input file
			in the format (line,file)
			corresponding to the given output line number, or
			(?,?) if unable to map back.
	'''
	def map_line_to_input_file(self, lineno):
		nextkey = 0
		inputfile = ''

		if lineno in self.outputtoinput:
			firstkey = nextkey = lastkey = lineno

			if nextkey in self.outputtoinput and nextkey != 0:
				lastkey = nextkey
				nextkey = self.outputtoinput[nextkey]
			else:
				nextkey = 0
			if nextkey!=0 and lastkey in self.outputtofiles:
				inputfile = self.outputtofiles[lastkey]

		if nextkey == 0: nextkey = '?'
		if inputfile == '': inputfile = '?'

		return (nextkey, inputfile)


def main():
	parser = argparse.ArgumentParser(description="Build a function call graph from a C file, check which functions must be retested")
	parser.add_argument("input", help="Input C source file")
	parser.add_argument("-o", "--old", help="Old version of the C file")
	parser.add_argument("-l", "--lines", help="Comma-separated list of changed lines", default="")
	parser.add_argument("-f", "--functions", help="Comma-separated list of changed functions", default="")
	parser.add_argument("--caller-depth", type=int, default=1, help="Depth of caller tree for retesting (use -1 for max depth)")
	parser.add_argument("--callee-depth", type=int, default=0, help="Depth of callee tree for retesting (use -1 for max depth)")
	parser.add_argument("-A", "--show-ast", action='store_true', help="show file AST and exit (skip analysis)")
	parser.add_argument("-g", "--graphic", help="save function call graph in a .dot file", default="")
	parser.add_argument("-n", "--new-tag", help="save change log for new release tag", default="")
	parser.add_argument("-I", "--include", help="include paths", default="")
	args = parser.parse_args()

	sig_changes = set()
	
	builder = CallGraphBuilder()
	builder.inputfile = args.input
	
	if not args.show_ast:
		lib_funcs = set()
		lines = args.lines
		if lines: 
			print("changed lines are " + lines)
			builder.target_lines = {int(x.strip()) for x in lines.split(",") if x.strip()}
		functions = args.functions
		if functions:
			lib_funcs = {str(x.strip()) for x in functions.split(",") if x.strip()}
			builder.changed_func.update(lib_funcs)
	
	
		if args.old:
			old_input = printFileRows(args.old)
			# old_builder = CallGraphBuilder() # TODO: use this version later
			old_self, old_ast = builder.preprocess_and_run(old_input, args.old, args.include)

			# print("\nFunction Call Graph (old version):")
			# for caller, callees in old_call_graph.items():
			#	 print(f"{caller}: calls -> {', '.join(callees) if callees else 'None'}")

	builder.newvisit = True
	input = printFileRows(args.input)
	new_self, new_ast = builder.preprocess_and_run(input, args.input, args.include, args.show_ast)
	

	if args.old: 
		old_func_info = extract_func_params(old_ast)
		new_func_info = extract_func_params(new_ast)
	
		old_func_names = set(old_func_info.keys())
		new_func_names = set(new_func_info.keys())		
		funcs_in_both = old_func_names.intersection(new_func_names)

		for func in funcs_in_both:
			# print("function is "+str(func))

			# entry is a tuple [[params node], coordinates, [return types]]
			old_entry = old_func_info.get(func) 
			new_entry = new_func_info.get(func)

			# number of parameters
			old_param_count = 0
			new_param_count = 0
			if old_entry[0] is not None:
				old_param_count = len(old_entry[0]) 
			if new_entry[0] is not None:
				new_param_count = len(new_entry[0])
			
			# return type of the function
			old_ret_type = old_entry[2]
			new_ret_type = new_entry[2]


			if old_ret_type != new_ret_type:
				line, file = builder.map_line_to_input_file(new_entry[1].line)
				sig_changes.add(func)
				print(f"Function '{func}' changed return type: {str(old_ret_type)} → {str(new_ret_type)} (check line {line})")
			if new_param_count>old_param_count and new_param_count>0:
				for i,param in enumerate(new_entry[0]):
					param_type_new = param 
					# if the param is a pointer, it has an extra type field, so we have to dig on types until we eventually find the param name
					if isinstance(param_type_new,pycparser.c_ast.EllipsisParam):
							param_type_new = new_param_count = "Variadic"
					while hasattr(param_type_new,'type'):
						# print(" 5555 %s " % (param_type_new))
						if hasattr(param_type_new.type, "names"): 
							quals = param_type_new.quals
							param_type_new = param_type_new.type.names
							param_type_new[:0] = quals
							break
						param_type_new = param_type_new.type
					param_type_old = old_entry[0][i] if i<old_param_count else None
					if param_type_old is not None:
						if isinstance(param_type_old,pycparser.c_ast.EllipsisParam):
							param_type_old = old_param_count = "Variadic"
						# if the param is a pointer, it has an extra type field, so we have to dig on types until we eventually find the param name
						# found = False
						while hasattr(param_type_old,'type'):
							# print(" 5555 %s " % (param_type_old))
							if hasattr(param_type_old.type, "names"):
								# found = True
								quals = param_type_old.quals 
								param_type_old = param_type_old.type.names
								param_type_old[:0] = quals 
								break
							param_type_old = param_type_old.type # TODO: write an error message in case attribute names is never found (there is a sketch commented out already)
						# if not found: print("param not found")
					if param_type_old is not None and set(param_type_new)!=set(param_type_old): # converted to set because order of modifiers do not matter (e.g. short signed and signed short should be treated the same)
						line, file = builder.map_line_to_input_file(new_entry[1].line) 
						sig_changes.add(func)
						print(f"Function '{func}' changed parameters type: parameter #{i+1} was {str(param_type_old)} and now is {str(param_type_new)} (check line {line})")
						break
			elif old_param_count>1:
				for i,param in enumerate(old_entry[0]):
					param_type_old = param
					if isinstance(param_type_old,pycparser.c_ast.EllipsisParam):
						param_type_old = old_param_count = "Variadic"
					# if the param is a pointer, it has an extra type field, so we have to dig on types until we eventually find the param name
					while hasattr(param_type_old,'type'):
						# print(" 5555 %s " % (param_type_new))
						if hasattr(param_type_old.type, "names"): 
							quals = param_type_old.quals 
							param_type_old = param_type_old.type.names
							param_type_old[:0] = quals
							break
						param_type_old = param_type_old.type
					param_type_new = new_entry[0][i] if i<new_param_count else None
					if param_type_new is not None:
						if isinstance(param_type_new,pycparser.c_ast.EllipsisParam): # TODO: double check if we need any treatment here
							param_type_new = new_param_count = "Variadic"
						# if the param is a pointer, it has an extra type field, so we have to dig on types until we eventually find the param name
						while hasattr(param_type_new,'type'):
							# print(" 5555 %s " % (param_type_old)) # -D
							if hasattr(param_type_new.type, "names"): 
								quals = param_type_new.quals
								param_type_new = param_type_new.type.names
								param_type_new[:0] = quals
								break
							param_type_new = param_type_new.type
					if param_type_new is not None and set(param_type_new)!=set(param_type_old): # converted to set because order of modifiers do not matter (e.g. short signed and signed short should be treated the same)
						line, file = builder.map_line_to_input_file(new_entry[1].line) 
						sig_changes.add(func)
						print(f"Function '{func}' changed parameters type: parameter #{i+1} was {str(param_type_old)} and now is {str(param_type_new)} (check line {line})")
						break
			if old_param_count != new_param_count:
				line, file = builder.map_line_to_input_file(new_entry[1].line) 
				sig_changes.add(func)
				print(f"Function '{func}' changed parameter count: {old_param_count} → {new_param_count} (check line {line})")
			

		for name in old_func_names - new_func_names:
			old_node = old_func_info[name]
			old_self.removed_funcs.add(name)
			line, file = builder.map_line_to_input_file(old_node[1].line) 
			print(f"Removed function '{name}' from line {line}") # TODO: double check line mapping for old version of the file
	
	
		for name, new_func in builder.funcdefs_new.items():
			old_func = builder.funcdefs_old.get(name)
			if not old_func:
				builder.new_funcs.add(name)
				line, file = builder.map_line_to_input_file(new_func.decl.coord.line)
				print(f"Function '{name}' is new (declared at line {line})")
			else:
				# print(f"Matched function '{name}' at lines {old_func.decl.coord.line} (old) and {new_func.decl.coord.line} (new)")
				if not ast_equal(old_func, new_func):
					builder.changed_func.add(name)
					line, file = builder.map_line_to_input_file(new_func.decl.coord.line)
					print(f"Function '{name}' has changed (check line {line})")
	
	# print(self.changed_func)
	print("\n--- Functions map:")
	for caller, callees in builder.call_graph.items():
		print(f"{caller} calls: {', '.join(callees)}")
	if args.graphic: save_call_graph_to_dot(builder.call_graph, args.graphic+".dot") # TODO: refine image (add line numbering, function signature, filename etc.)
	
	printed = set()          # to avoid showing the same function twice
	retest_set = set()       # caller/callee functions that must be retest
	next_retest_set = set()  # next depth of functions to check
	depth_up = 0             # how far up in the function call graph we went
	depth_down = 0           # how far down in the function call graph we went
	changed_map = {}         # map from files to changed functions

	# retesting output
	if builder.changed_func: # TODO: check if this condition is necessary and sufficient to show the retesting output
		if lib_funcs!=builder.changed_func: print("functions changed: " + " ".join(builder.changed_func))
		print("\n--- Functions that need retest are: ")
		for f in builder.changed_func:
			print(f+" (changed)")
			reverse_graph = invert_call_graph(builder.call_graph)
			printed.add(f)
			# navigate up the tree using the reverse graph
			if f in reverse_graph.keys() and args.caller_depth>0:
				retest_set.update(reverse_graph[f])
				depth_up += 1
				msg = " (direct caller(s) of %s)" % f 
				if bool(retest_set.difference(printed)): print(str(retest_set.difference(printed)) + msg)
				printed.update(retest_set)
				while depth_up<args.caller_depth:
					for ff in retest_set:
						if ff in reverse_graph.keys() and bool(reverse_graph[ff].difference(printed)):
							msg = " (indirect caller(s) of %s)" % f 
							print(str(reverse_graph[ff].difference(printed)) + msg)
							printed.update(reverse_graph[ff])
							next_retest_set.update(reverse_graph[ff])
					retest_set = next_retest_set.copy()
					depth_up += 1
					next_retest_set.clear()
			retest_set.clear() # clear set to use it for callees now
			# navigate down the tree
			if f in builder.call_graph.keys() and args.callee_depth>0:
				retest_set.update(builder.call_graph[f])
				depth_down += 1
				msg = " (direct callee(s) of %s)" % f 
				if bool(retest_set.difference(printed)): print(str(retest_set.difference(printed)) + msg)
				printed.update(retest_set)
				while depth_down<args.callee_depth:
					for ff in retest_set:
						if ff in builder.call_graph.keys() and bool(builder.call_graph[ff].difference(printed)):
							msg = " (indirect callee(s) of %s)" % f 
							print(str(builder.call_graph[ff].difference(printed)) + msg) 
							printed.update(builder.call_graph)
							next_retest_set.update(builder.call_graph[ff])
					retest_set = next_retest_set.copy()
					depth_down += 1
					next_retest_set.clear()
		changed_map[builder.inputfile] = builder.changed_func
		save_dict_as_python_file(changed_map, "changed_map.py")
	else:
		print("\n--- no functions changed ---")

	if args.new_tag:
		# print("Saving log\n")
		save_change_log(args.input, args.new_tag, changed_map, old_self.removed_funcs, new_self.new_funcs, sig_changes)


if __name__ == "__main__":
	main()

