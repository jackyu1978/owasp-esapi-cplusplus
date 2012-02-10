==========================================================================
Setting up BOOST for building esapi on windows using Visual Studio 8/9/10
==========================================================================

Download the Boost Distribution.
http://www.boost.org/users/history/version_1_47_0.html  was the source I used for this release.
Hopefully newer versions don't change too much.

Extract the zip file into the directory where you keep ThirdPartyLibraries
in my case 
	C:\SoftwareDevelopment\ThirdPartyLibs

Use Start->Computer->(RightClick)->Properties->Advanced System Settings Environment Variables
Add an Environment variable  BOOST_ROOT with a value of where you just unzipped Boost
BOOST_ROOT=C:\SoftwareDevelopment\ThirdPartyLibs\boost_1_47_0

Open C:\SoftwareDevelopment\ThirdPartyLibs\boost_1_47_0\index.html.  It has the instructions you need.
I'm repeating the important points here anyway.  If versions change, the supplied documentation
is probably more correct, but at that point I can't help you anymore.

The forum thread at 
http://stackoverflow.com/questions/2322255/64-bit-version-of-boost-for-64-bit-windows
helped quite a bit in figuring this out.

--- 

Open a Visual Studio Command Window.

Make the boost directory current  (cd %BOOST_ROOT% should work).

from the command line run bootstrap.bat

when it finishes, run .\b2.exe

If you have only one compiler and target, then you're possibly done.
I don't know, I'm not in that situation.


For my situation I needed to be able to use Boost for 
	Visual Studio 8(2005)
	Visual Studio 9(2008) 
	and Visual Studio 10(2010).
I also needed to be able to built for both Win32 (x86) and x64 targets.
Fun,fun,fun.

So once it finished, I deleted stage\lib
I just needed the prior step to make sure all the boost auto-build tools are properly installed, built and configured.

Anyway, delete what it built, because since it depends on various "auto-detection"
strategies, you don't really know what it built. 


So we start over.  Methodically, in little sandboxes so we know what we're getting.


---

Go to the main Start->VisualStudio Menu Item for 2008->VisualStudio Tools->Command Prompt
In that command window, cd to %BOOST_ROOT%

Execute: 
bjam --toolset=msvc-9.0 --build-type=complete --stagedir=VS9\Win32

FinalOutput:
The Boost C++ Libraries were successfully built!

The following directory should be added to compiler include paths:

    C:/SoftwareDevelopment/ThirdPartyLibs/boost_1_47_0

The following directory should be added to linker library paths:

    C:\SoftwareDevelopment\ThirdPartyLibs\boost_1_47_0\VS9\Win32\lib


--- 

Now go to the main Start->VisualStudio Menu Item for 2008->VisualStudio Tools->x64 Win64 Command Prompt
In that command window, cd to %BOOST_ROOT%

Execute: 
bjam --toolset=msvc-9.0 address-model=64 --build-type=complete --stagedir=VS9\x64



FinalOutput:
The Boost C++ Libraries were successfully built!

The following directory should be added to compiler include paths:

    C:/SoftwareDevelopment/ThirdPartyLibs/boost_1_47_0

The following directory should be added to linker library paths:

    C:\SoftwareDevelopment\ThirdPartyLibs\boost_1_47_0\VS9\x64\lib

---


Now go to the Start->VisualStudio Menu Item for 2010->VisualStudio Tools->Command Prompt
In that command window, cd to %BOOST_ROOT%

Execute: 
bjam --toolset=msvc-10.0  --build-type=complete --stagedir=VS10\Win32

FinalOutput:
The Boost C++ Libraries were successfully built!

The following directory should be added to compiler include paths:

    C:/SoftwareDevelopment/ThirdPartyLibs/boost_1_47_0

The following directory should be added to linker library paths:

    C:\SoftwareDevelopment\ThirdPartyLibs\boost_1_47_0\VS10\Win32\lib

---

Now go to the Start->VisualStudio Menu Item for 2010->VisualStudio Tools->x64 Win64 Command Prompt
In that command window, cd to %BOOST_ROOT%

Execute: 
bjam --toolset=msvc-10.0 address-model=64   --build-type=complete --stagedir=VS10\x64

FinalOutput:
The Boost C++ Libraries were successfully built!

The following directory should be added to compiler include paths:

    C:/SoftwareDevelopment/ThirdPartyLibs/boost_1_47_0

The following directory should be added to linker library paths:

    C:\SoftwareDevelopment\ThirdPartyLibs\boost_1_47_0\VS10\x64\lib

---

Go to the main Start->VisualStudio Menu Item for 2005->VisualStudio Tools->Command Prompt
In that command window, cd to %BOOST_ROOT%

Execute: 
bjam --toolset=msvc-8.0 --build-type=complete --stagedir=VS8\Win32

FinalOutput:
The Boost C++ Libraries were successfully built!

The following directory should be added to compiler include paths:

    C:/SoftwareDevelopment/ThirdPartyLibs/boost_1_47_0

The following directory should be added to linker library paths:

    C:\SoftwareDevelopment\ThirdPartyLibs\boost_1_47_0\VS8\Win32\lib


--- 

Go to the main Start->VisualStudio Menu Item for 2005->VisualStudio Tools->Command Prompt
In that command window, cd to %BOOST_ROOT%

Execute: 
bjam --toolset=msvc-8.0 address-model=64  --build-type=complete --stagedir=VS8\x64

FinalOutput:
The Boost C++ Libraries were successfully built!

The following directory should be added to compiler include paths:

    C:/SoftwareDevelopment/ThirdPartyLibs/boost_1_47_0

The following directory should be added to linker library paths:

    C:\SoftwareDevelopment\ThirdPartyLibs\boost_1_47_0\VS8\x64\lib


--- 

The esapi-cplusplus solutions files should have the library paths set correctly,
presuming the environment variables are set properly.

The BOOST env variable should be BOOST_ROOT and it should be set to 
	C:\SoftwareDevelopment\ThirdPartyLibs\boost_1_47_0,
assuming that is where you unzipped things in step one.