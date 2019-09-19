# vac-hooks
Hook WinAPI functions used by Valve Anti-Cheat. Log calls and intercept arguments & return values. DLL written in C.

## Getting started

### Prerequisites
Microsoft Visual Studio 2019 (preferably latest version i.e. 16.1.6), platform toolset v142 and Windows SDK 10.0 are required in order to compile vac-hooks. If you don't have ones, you can download VS [here](https://visualstudio.microsoft.com/) (Windows SDK is installed during Visual Studio Setup).

### Cloning
The very first step in order to compile vac-hooks is to clone this repo from GitHub to your local computer. Git is required to step futher, if not installed download it [here](https://git-scm.com). Open git bash / git cmd / cmd and enter following command:
```
git clone https://github.com/danielkrupinski/vac-hooks.git
```
`vac-hooks` folder should have been succesfully created, containing all the source files.

### Compiling from source

When you have equiped a copy of source code, next step is opening **vac-hooks.sln** in Microsoft Visual Studio 2019.

Then change build configuration to `Release | x86` and simply press **Build solution**.

If everything went right you should receive `vac-hooks.dll`  binary file.

### Loading

Open **Steam** as Administrator, then open your favorite [DLL injector](https://en.wikipedia.org/wiki/DLL_injection) (as an admin too) and inject `vac-hooks.dll` into `Steam.exe` process.

After injection you should see `vac-hooks.txt` log file in **Steam installation directory** (e.g. `C:\Program Files (x86)\Steam`). The log file contains names of WinAPI functions being called by VAC, their parameters and return values.

## See also
- [VAC](https://github.com/danielkrupinski/vac) - source code of Valve Anti-Cheat obtained from disassembly of compiled modules