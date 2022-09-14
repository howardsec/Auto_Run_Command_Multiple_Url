#!/usr/bin/env python3

import os, sys, re

#command = sys.argv[1]
command = "curl --insecure -s "
#allTarget = sys.argv[2]
allTarget = sys.argv[1]
#parameter = sys.argv[3]
parameter = "cmd.exe"
#resultPath = sys.argv[4]
resultPath = "result"

targetList = open(allTarget, "r")

# Search Text is Match ?
def matchContent(self, regex, attack=True):
    r = self
    if r is None:
        return
    # We may need to match multiline context in response body
    if re.search(regex, r, re.I):
        return True
    return False

# SecureSphere Error Page Info
def securesphere(self):
    schemes = [
        matchContent(self, r'<(title|h2)>Error'),
        matchContent(self, r'The incident ID is'),
        matchContent(self, r"This page can't be displayed"),
        matchContent(self, r'Contact support for additional information')
    ]
    if all(i for i in schemes):
        return True
    return False

if not os.path.isdir(resultPath):
    os.mkdir(resultPath)

for oneSite in targetList.readlines():
    # Run OS Command
    scanCommand = command + oneSite[:-1] + parameter
    scanResult = os.popen("%s" %scanCommand).read()
    identifyResult = securesphere(scanResult)

    # Write Result to File.
    resultName = 'result.txt'
    makeResult = open(os.path.abspath(resultPath) + "//" + resultName, "a")
    makeResult.write(scanCommand + "\n")
    makeResult.write(str(identifyResult) + "\n")
    makeResult.close()
