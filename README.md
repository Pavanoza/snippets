#author pavan
# snippets
Various code snippets and small PoCs, to be used for tests or as ready-made skeletons.
+ <b>demo_dll</b> - a small sample DLL with 2 exported functions
+ <b>demoCalc_dll</b> - a small sample DLL (in masm) deploying calc.exe on load
+ <b>drop_and_run</b> - an EXE dropping and loading a DLL (stored in resources)
+ <b>inject1</b> - injecton demo - patches Entry Point of calc.exe
+ <b>inject2</b> - injection demo - adds a thread with shellcode to calc.exe
+ <b>inject3</b> - injection demo - injects shellcode to calc.exe using NtQueueApcThread
+ <b>inject4</b> - injection demo - injects full image self (as a new section), applies relocations and deploys a function
+ <b>neutrino_env_check.cpp</b> - Set of defensive environment checks - against VM, sandbox, monitoring tools etc. Implementation based on Neutrino Bot Loader.
