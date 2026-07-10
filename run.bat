@echo off
cd /d D:\C++

call "%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cl helloWorld.cpp /std:c++20 /EHsc
if %errorlevel%==0 helloWorld.exe

pause