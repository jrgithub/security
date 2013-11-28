'''
The authors have no affiliation with Tenable Network Security (providers of the NESSUS software) 
and this software has not been endorsed by Tenable Network Security.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
'''

'''
This script will parse a .nessus file for common fields and print their respective values.
'''

#!/usr/bin/env python

import xml.etree.ElementTree as ET
import sys

file = open(sys.argv[1], "r")

tree = ET.parse(file)

root = tree.getroot()
 
for child in root:

	for child2 in child:
		if "ReportHost" in child2.tag:
			print "*******************NEW HOST*****************************"
			print "Resource(s): " + child2.get('name')  + '\n'
		for child3 in child2:
			
			if "ReportItem" in child3.tag:
				
				if len(child3.get('pluginName')) > 1:
					print "********************************"
					print "Issue: " + child3.get('pluginName') + '\n'
					print "Severity: " + child3.get('severity') + '\n'

				for child4 in child3:
					
					if "solution" in child4.tag:
						print "Solution: " + str(child4.text)  + '\n'
 					if "risk_factor" in child4.tag:
						print "Risk Factor: " + str(child4.text)  + '\n'
 					if "description" in child4.tag:
						print "Description: " + str(child4.text)  + '\n'
 					if "synopsis" in child4.tag:
						print "Synopsis: " + str(child4.text)  + '\n'
 					if "patch_publication_date" in child4.tag:
						print "Patch Publication Date: " + str(child4.text)  + '\n'
 					if "see_also" in child4.tag:
						print "Reference(s): " + str(child4.text)  + '\n'
 					if "cvss_base_score" in child4.tag:
						print "CVSS Base Score: " + str(child4.text)  + '\n'
 					if "plugin_output" in child4.tag:
						print "Plugin Output: " + str(child4.text)  + '\n'

		
