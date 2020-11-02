@echo off
title Windows Makefile for Mochimo Software
REM
REM   Copyright (c) 2019 by Adequate Systems, LLC.  All Rights Reserved.
REM   See LICENSE.PDF   **** NO WARRANTY ****
REM
REM   Date: 3 August 2019
REM
echo.


REM ################
REM Variable localization and Delayed expansion
setlocal ENABLEDELAYEDEXPANSION


REM ################
REM Double-click batch file fallback
if "%1"=="" (
   echo No commands were detected.
   echo Initiating Double-click startup...
   call :fnUSAGE
   set /p userinput="%~dp0> "
   if "!userinput!"=="" EXIT
   cls
   echo "%~dp0> !userinput!"
   call !userinput!
   pause
   EXIT
)


REM ################
REM Initialize environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat"
if %errorlevel% NEQ 0 (
   echo Failed to Initialize Visual Studio x64 Developer command prompt
   echo Please ensure Microsoft Visual Studio 2017 Community Edition has
   echo been correctly installed and your machine architecture is x64.
   goto END
)


REM ################
REM Initialize globals
set ERRORS=0
set WARNINGS=0
set NEWERRORS=0
set NEWWARNINGS=0
set CUDANODE=0
set CUDA_GENCODE=""


REM ################
REM Check Supported Commands
set COMMANDS="worker wallet test_miner clean install uninstall"
echo %COMMANDS% | find "%1" >NUL
if %errorlevel% EQU 0 goto OPTIONS
echo "Unsupported command"
call :fnUSAGE
goto END


REM ################
REM Determine command options
:OPTIONS
echo.
echo "%*" | find "-DCUDA" > NUL
if %errorlevel% EQU 0 (
   set CUDANODE=1
   echo CUDA Compilation activated.
) else (
   echo CPU Compilation activated.
)
echo.


REM ################
REM Perform sanity checks
echo | set /p="Sanity checks... "

dir /b "mochimo.c" > NUL
if %errorlevel% NEQ 0 (
   echo Error
   echo You need to be in mochi/src
   goto END
)
if "%1"=="uninstall" (
   dir /ad /b "../bin"
   if !errorlevel! NEQ 0 (
      echo Error
      echo Cannot find installation directory mochimo/bin
      goto END
   )
   dir /ad /b "../bin/d"
   if !errorlevel! NEQ 0 (
      echo Error
      echo Cannot find working directory mochimo/bin/d
      goto END
   )
)
if %CUDANODE% EQU 1 (
   nvcc --version >>ccerror.log 2>&1
   if !errorlevel! NEQ 0 (
      echo Failed to find Nvidia CUDA Compiler.
      echo Please ensure an appropriate Cuda Toolkit has been correctly
      echo installed AFTER your Microsoft Visual Studio installation.
      goto END
   )
)

echo Done


REM ################
REM Preconfiguration
echo | set /p="Preconfiguration... "

REM Reset error log
del /f /q "ccerror.log" 1>NUL 2>&1
echo. 2>ccerror.log 1>NUL

REM Preconfigure CUDA
if %CUDANODE% EQU 1 call :fnGETCUDACOMPUTE

call :fnCHECKERRLOG


REM ################
REM Process command

if "%1"=="worker" goto worker
if "%1"=="clean" goto clean
goto END

REM Compile the Mochimo worker
:worker
   echo | set /p="Make dependencies... "
   cl /nologo /DWIN32 /c crypto\hash\cpu\sha256.c >>ccerror.log 2>&1
   cl /nologo /DWIN32 /c algo\trigg\trigg.c >>ccerror.log 2>&1
   call :fnCHECKERRLOG
   if %CUDANODE% EQU 1 (
      echo | set /p="Make cuda objects... "
      nvcc -DWIN32 %CUDA_GENCODE% -c algo\peach\cuda_peach.cu >>ccerror.log 2>&1
      call :fnCHECKERRLOG
      echo | set /p="Building Mochimo worker... "
      cl /nologo /DWIN32 /DCUDA /Feworker.exe worker.c trigg.obj sha256.obj cuda_peach.obj /I%NVCC_INCLUDE% /link /LIBPATH:%NVCC_LIB% >>ccerror.log 2>&1
   ) else (
      echo | set /p="Building Mochimo worker... "
      cl /nologo /DWIN32 /Feworker.exe worker.c trigg.obj sha256.obj  >>ccerror.log 2>&1
   )
   REM Display Summary
   call :fnCHECKERRLOG "full"
   REM Cleanup object files
   del /f /q "worker.obj" "sha256.obj" "wots.obj" "trigg.obj" "cuda_peach.obj"
   goto END

REM Clean Mochimo compilation files
:clean
   echo | set /p="Cleanup... "
   del /f /q "worker.obj" "sha256.obj" "wots.obj" "trigg.obj" "cuda_peach.obj" "worker.exe" "ccerror.log"
   echo Done
   goto END

REM END
:END
   echo.
   pause
   EXIT

REM Usage
:fnUSAGE
   echo.
   echo Usage: makewin [command] [options]
   echo    command: worker        make only the worker binary program
   echo             wallet        make only the wallet binary program
   echo             test_miner    make only a test case specified by *
   echo             clean         remove object files and log files
   echo             install       copy binaries and run scripts to ../bin
   echo             uninstall     remove files from mochi/bin directory tree
   echo    options: -DCUDA        force miner to use CUDA [NVIDIA]
   echo.
   EXIT /B 0

REM Function to get CUDA Compute Capabilities
:fnGETCUDACOMPUTE
   nvcc -o getcudacompute.exe getcudacompute.cu >>ccerror.log 2>&1
   for /F "tokens=* USEBACKQ" %%i in (`getcudacompute.exe`) do @set CUDA_GENCODE=%%i
   del /f /q "getcudacompute.exe" "getcudacompute.lib" "getcudacompute.exp"
REM set CUDA_GENCODE=""
   if %CUDA_GENCODE%=="" (
      echo.
      echo Unable to automatically determine GPU compute level.
      echo | set /p="Using defaults... "
      REM https://arnon.dk/matching-sm-architectures-arch-and-gencode-for-various-nvidia-cards/
      set "CUDA_GENCODE=-gencode arch=compute_52,code=sm_52 -gencode arch=compute_61,code=sm_61 -gencode arch=compute_75,code=sm_75 -gencode arch=compute_86,code=sm_86"
   )
   REM Determine CUDA include and library directories
   for /F "delims=" %%i in ('where /F nvcc') do (
      @set NVCC_PATH=%%i
      goto breaknvccpath
   )
   :breaknvccpath
   set NVCC_INCLUDE=%NVCC_PATH:bin\nvcc.exe=include%
   set NVCC_LIB=%NVCC_PATH:bin\nvcc.exe=lib\x64%
   EXIT /B 0

REM Function to check for errors
:fnCHECKERRLOG
   if NOT EXIST ccerror.log (
      echo No log found
      EXIT /B 1
   )
   for /f "tokens=2delims=:" %%a in ('find /c "error" ccerror.log') do @set /a NEWERRORS+=%%a
   for /f "tokens=2delims=:" %%a in ('find /c "warning" ccerror.log') do @set /a NEWWARNINGS+=%%a
   if %NEWERRORS% NEQ %ERRORS% (
      echo Errors
   ) else if %NEWWARNINGS% NEQ %WARNINGS% (
      echo Warnings
   ) else (
      echo Done
   )
   set ERRORS=%NEWERRORS%
   set WARNINGS=%NEWWARNINGS%
   if "%~1"=="" EXIT /B 0
   if %ERRORS% EQU 0 if %WARNINGS% EQU 0 (
      echo.
      echo Done. No Errors.
      EXIT /B 0
   )
   echo ccerror.log contains:
   echo   %ERRORS% Errors
   echo   %WARNINGS% Warnings
   echo   check the log for details...
   where /T ccerror.log
   EXIT /B 0
