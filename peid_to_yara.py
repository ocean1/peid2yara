#!/usr/bin/env python
# encoding: utf-8
#
# Tested on Linux (Ubuntu), Windows XP/7, and Mac OS X
#
"""
untitled.py

Created by Matthew Richard on 2010-03-12.
Copyright (c) 2010. All rights reserved.
"""

import sys
import os
import re
from optparse import OptionParser
from collections import OrderedDict

def main():
	parser = OptionParser()
	parser.add_option("-f", "--file", action="store", dest="filename",
	             type="string", help="scanned FILENAME")
	parser.add_option("-o", "--output-file", action="store", dest="outfile",
			type="string", help="output filename")
	parser.add_option("-v", "--verbose", action="store_true", default=False,
					dest="verbose", help="verbose")
	parser.add_option("-n", "--no-ep", action="store_true", default=False,
					dest="no_ep", help="no entry point restriction")

	(opts, args) = parser.parse_args()

	if opts.filename == None:
		parser.print_help()
		parser.error("You must supply a filename!")
	if not os.path.isfile(opts.filename):
		parser.error("%s does not exist" % opts.filename)
		
	if opts.outfile == None:
		parser.print_help()
		parser.error("You must specify an output filename!")
		
	# yara rule template from which rules will be created
	yara_rule = u"""
rule %s
{
    meta:
        name = "%s"
    strings:
        %s
    condition:
        %s
}
	
	"""
	rules = {}
	
	# read the PEiD signature file as the first argument
	data = open(opts.filename, 'rb').read()

	# every signature takes the form of
	# [signature_name]
	# signature = hex signature
	# ep_only = (true|false)
	signature = re.compile('^\[(.+?)\]\r?\nsignature = (.+?)\r?\nep_only = (.+?)\r?\n', re.M|re.S|re.I)
	
	matches = signature.findall(data)
	if opts.verbose:
		print "Found %d signatures in PEiD input file(s)" % len(matches)

	names = {}
	mdict = {}
	#get only the rules that do not overlap
	for match in matches:
		if match[0] not in mdict:
			mdict[match[0]] = match

	matches = OrderedDict(sorted(mdict.items(), key=lambda t: t[0]))
	for match in matches.values():
		name = match[0].__repr__()
		# yara rules can only contain alphanumeric + _
		try:
			match[0].decode('ascii')
			rulename = match[0]
		except Exception as e:
			#should we have some unicode chars
			#or something strange ...get representation!
			rulename = match[0].__repr__()
			try:
				#try decoding some chinese charsets into utf8
				name = match[0].decode('GB2312')
			except:
				try:
					name = match[0].decode('GBK')
				except:
					# give up!
					print "can't decode %s" % match[0].__repr__()
		re.search

		rulename_regex = re.compile('(\W)')
		rulename = rulename_regex.sub('', rulename)


		# and cannot start with a number
		rulename_regex = re.compile('(^[0-9]{1,})')
		if rulename_regex.sub('', rulename) == '':
			rulename = 'packer'+rulename
		else:
			rulename = rulename_regex.sub('', rulename)


		# if the rule doesn't exist, create a dict entry
		if rulename not in rules:
			rules[rulename] = []
			#delete strange combinations of quote/dquote
			name = re.sub("(^('|\")|('|\")$|\")",'',name)
			name = re.sub("^\*\s",'',name)
			names[rulename] = name
		
		signature = match[1]

		# add the rule to the list
		rules[rulename].append((signature, match[2]))

	output = u''
	
	for rule in rules.keys():
		detects = ''
		mod_ep = False
		conds = '\t'
		x = 0
		try:
			for (detect, ep) in rules[rule]:
				# check for rules that start with wildcards
				# this is not allowed in yara, nor is it particularly useful
				# though it does goof up signatures that need a few wildcards
				# at EP
				while detect[:3] == '?? ':
					detect = detect[3:]
					if opts.no_ep == True:
						if opts.verbose:
							print "\t\tSince you said no_ep, I'll skip the ep."
						mod_ep == True
					if opts.verbose:
						print "\tTrimming %s due to wildcard at start" % names[rule]
				# create each new rule using a unique numeric value
				# to allow for multiple criteria and no collisions

				# try to find rules which contains invalid characters 
				jv_out = re.findall(r"([JV].|\s[A-F0-9]\s|\s[A-F0-9]$|[\:].)", detect)
				if jv_out:
					raise Exception("Cannot import %s, found %s" % (names[rule], jv_out) )

				detects += "\t$a%d = { %s }\r\n" % (x, detect)

				if x > 0: 
					conds += " or "
				
				# if the rule specifies it should be at EP we add
				# the yara specifier 'at entrypoint'
				if ep == 'true' and mod_ep == False:
					conds += "$a%d at entrypoint" % x
				else:
					conds += "$a%d" % x
				x += 1

			# add the rule to the output
			output += yara_rule % (rule, names[rule], detects, conds)
		except Exception as e:
			if opts.verbose:
				print "\t"+str(e)

	# could be written to an output file
	fout = open(opts.outfile, 'wb')
	fout.write(output.encode('utf-8'))
	fout.close()
	if opts.verbose:
		print "Wrote %d rules to %s" % (len(rules), opts.outfile)

if __name__ == '__main__':
	main()

