import sys
import os
import time
import json
import hashlib
import threading
from datetime import datetime, date

#Buffer Size to limit memory for large files
BUF_SIZE = 65536

#Base & configuration path variables
BasePath = '/etc/FileIntegrityMonitor/'
os.makedirs(os.path.dirname(BasePath), exist_ok=True)
configFilePath = BasePath + 'config.json';
hashFilePath = BasePath + 'hashFile.txt';

#Checks if hashfile exists
if(os.path.exists(hashFilePath) == False):
    hashFile = open(hashFilePath, "w");
    hashFile.close();
logFilePath = BasePath + 'log.txt'

#Checks if log file exists
if(os.path.exists(logFilePath) == False):
    logFilePath = open(logFilePath, "w");
    logFilePath.close();


#Data to be written to config
defaultConfig = { "fileExtensions": [".txt",".json",".pdf"]
         , "secondsUntilReVerify": 10
         , "secondsUntilUpdateHashes": 120
         , "printingOnlyAlerts": True
         , "loggingOutput": True
         , "loggingAlerts": True
         , "loggingVerification": False
         , "loggingHashUpdates": False
         , "maxLogFileDays": 10
         , "ScanPath": "HOME_DIRECTORY"
         }

#Serializing json
json_object = json.dumps(defaultConfig, indent=4)

#Checking if config exists and writing to config
if(os.path.exists(configFilePath) == False):
    with open(configFilePath, "w") as outfile:
        outfile.write(json_object);

#Storing config.json lines into variables
def storeVariables():
    with open(configFilePath, "r") as f:
        configData = json.load(f);
        global fileExtensions
        fileExtensions = configData["fileExtensions"]
        global secondsUntilReVerify
        secondsUntilReVerify = configData["secondsUntilReVerify"]
        global secondsUntilUpdateHashes
        secondsUntilUpdateHashes = configData["secondsUntilUpdateHashes"];
        global printingOnlyAlerts
        printingOnlyAlerts = configData["printingOnlyAlerts"];
        global loggingOutput
        loggingOutput = configData["loggingOutput"];
        global maxLogFileDays
        maxLogFileDays = configData["maxLogFileDays"];
        global loggingAlerts
        loggingAlerts = configData["loggingAlerts"];
        global loggingHashUpdates
        loggingHashUpdates = configData["loggingHashUpdates"];
        global loggingVerification
        loggingVerification = configData["loggingVerification"];
        global ScanPath
        ScanPath = configData["ScanPath"];
storeVariables();

#Checks log file time to see if it pass its max
def checkLogFileTime():
    
    #Calculates current time of life of file
    st=os.stat(logFilePath);
    age = (time.time() - st.st_mtime);
    
    #Converting maxLogFileTime from days to seconds
    secondsMaxLogFileTime = maxLogFileDays * 86400

    #Checks if age of file is greater than max
    if(age >= secondsMaxLogFileTime):
        
        #writes over file so its empty
        print("Log File was deleted. Surpassed total max life");
        open(logFilePath, "w+");

#Creating SHA256 variable
sha256 = hashlib.sha256()

#Regenerating the hashes
def generateHashes():
    
    #Creates a thread and sets a timer to run generateHashes function every X amount seconds
    threading.Timer(secondsUntilUpdateHashes, generateHashes).start();
    sha256_returned = '';
    
    #Opening Hashfile
    hashFile = open(hashFilePath,'w+');
    logFile = open(logFilePath,'a');
    print("-"*40);
    for filename in os.listdir(ScanPath):
        
        #Line below grabs extension and puts it in string variable
        ext = os.path.splitext(filename)[-1].lower()
        
        # The * means it collects every type of file extension
        if(ext in fileExtensions or "*" in fileExtensions):
            if(os.path.isdir(ScanPath + filename)):
                continue;
            with open(ScanPath + filename, 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    sha256.update(data)
                    sha256_returned = hashlib.sha256(data).hexdigest()
            date_time = time.strftime("%b %d %Y %-I:%M %p")
            hashFile.write(str(date_time) + " | " + filename + ': ' + sha256_returned + '\n');
            if(loggingOutput == True and loggingHashUpdates == True):
                logFile.write("[" + date_time + "] " + "Hashed file " + filename + " | sha256 " + sha256_returned + "\n");
            print("Hashed file " + filename + " @ " + date_time + " | sha256 " + sha256_returned);
    print("-"*40);
    hashFile.close();

#Checks Integrity of files
def checkIntegrity():
    
    #Creates a thread and sets a timer to run checkintegrity function every X amount seconds
    threading.Timer(secondsUntilReVerify, checkIntegrity).start();
    
    #Calculating current hash of file
    hashFile = open(hashFilePath,'r+');
    logFile = open(logFilePath,'a');
    for filename in os.listdir(ScanPath):
        
        #Skips over directories; Directories not supported yet
        if(os.path.isdir(ScanPath + filename)):
            continue;
        with open(ScanPath + filename, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha256.update(data);
                sha256_returned = hashlib.sha256(data).hexdigest();
    
    #Checks the original hash against the current hash
        lines = hashFile.readlines();
        date_time = time.strftime("%b %d %Y %-I:%M %p")
        for line in lines:
            if((filename in line)):
                if(sha256_returned not in line):
                    
                    #If file has been modified
                    print("");
                    print("\033[1;31;40m" + ScanPath + filename + " has been changed! | " + date_time + " \033[1;32;40m ");
                    print("Original: " + "SHA256 " + line.split(" ")[7].strip("\n") + "\033[1;31;40m");
                    print("Current: SHA256 " + sha256_returned + "\033[1;37;40m");
                    if(loggingOutput == True and loggingAlerts == True):
                        logFile.write("[" + date_time +"] " + ScanPath + filename + " has been changed!" + "\n");
                        logFile.write("[" + date_time +"] " + "Original: " + "SHA256 " + line.split(" ")[7].strip("\n") + "\n");
                        logFile.write("[" + date_time + "] " + "Current: SHA256 " + sha256_returned + "\n")
                    else:
                        
                        #If file has not been modified
                        if(printingOnlyAlerts == False):
                            print("");
                            print("\033[1;32;40m"+ ScanPath + filename + " is a verified file | " + date_time );
                            print("Original: " + "SHA256 " + line.split(" ")[7].strip("\n"));
                            print("Current: SHA256 " + sha256_returned +"\033[1;37;40m");
                        if(loggingOutput == True and loggingVerification == True):
                            logFile.write("[" + date_time +"]" + ScanPath + filename + " is a verified file" + "\n");
                            logFile.write("[" + date_time +"]" + "Original: " + "SHA256 " + line.split(" ")[7].strip("\n") + "\n");
                            logFile.write("[" + date_time + "]" + "Current: SHA256 " + sha256_returned + "\n")
    hashFile.close();


#Timer variable for timer delay in function
timer = time.time();

def main():
    checkLogFileTime();
    checkIntegrity();
    time.sleep(5);
    generateHashes();
main();
