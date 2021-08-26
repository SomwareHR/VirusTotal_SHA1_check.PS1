# VirusTotal SHA1 check


## Check the reputation of a file's SHA1, using Powershell and VirusTotal API key

![on Windows](VirusTotal_SHA1_check-Windows.png)

![on Linux](VirusTotal_SHA1_check-Linux.png)



## WHAT

A small pwsh script to check an overall reputation of a file's SHA1 using Powershell and VirusTotal.
It also checks one (or more) particular antivirus engine's result (in this example, ESET-NOD32).
This script does not upload file to VT, it only returns last scan status if SHA1 exists.



## WHY

A short pwsh exercise for something I use regularly.



## WHERE

Tested on:

+ Windows 10 with Powershell 7
+ Windows 10 with Powershell 5
+ Ubuntu 21.04 with Powershell 7
+ did not test with older versions of Powershell



## HOW

### Prerequisites:

+ Powershell 5 or 7
+ [VirusTotal API key](https://developers.virustotal.com/v3.0/reference#getting-started)

### Run

First, implement your VT API key. Originally, script makes use of environment variable "zzVirusTotalAPI":

```powershell
$swVTFileReportWR = Invoke-WebRequest -Method GET -Uri "https://www.virustotal.com/api/v3/files/$args" -Headers @{"x-apikey"="$Env:zzVirusTotalAPI"}
```

If you don't like the idea - hardcode API key:

```powershell
$swVTFileReportWR = Invoke-WebRequest -Method GET -Uri "https://www.virustotal.com/api/v3/files/$args" -Headers @{"x-apikey"="abcd1234efgh5678ijkl...blabla"}
```

After that, run the script and give it an argument:

```
VirusTotal_IP_check.ps1 malware.exe
```

### Error management

Script expects an argument from command line and it should be a filename (or full path).
There is minimal error management - checks if file exists and if VirusTotal replies with an error.

### ToDo

Nothing much if anything. It does what's expected - return a reputation.



## MISC

For test purposes, eicar.com sha1: 3395856CE81F2B7382DEE72602F798B642F14140



## WHEN, WHO

```
VirusTotal_IP_check.PS1 v.21.0824.18
(C)2021 SomwareHR
https://github.com/SomwareHR
License: MIT
[SWID#20210824064501]
```
