=================================================================
Building the Crypto++ Library 
for use with owasp-esapi-cplusplus library 
with the Visual Studion 2005 solution file  crypto530_VS8.sln
=================================================================
USING THIS SOULUTION FILE IS *NOT* COMPATIBLE WITH THE 
FIPS CERTIFIED VERSION OF THE Crypto++ LIBRARY

 - jAHOLMES (starfyr@jholmesassociates.com)  2012.02.05
=================================================================

The solution that includes this file (esapi_C530_VS8.sln) 
was an attempt to build esapi using the FIPS certified Crypto Library.

I never got it to work correctly.
I tried a great number of combinations of compiler and linker settings, 
but always came up with link errors 
(the number and names of functions missing varied depending on approach).


I saw the notes in the cryptopp readme.txt that hinted at this, 
but thought it could be resolved simply by tweaking the  project settings.   
After too many hours of head banging I finally realized something was wrong, 
and searched to see if there was an elaboration on what was said in the read me.  
I found this:

"The best solution is using the /NODEFAULTLIB switch and hoping that no runtime issues occur. 
This situation will create hard to track down runtime bugs and obscure initialization failures. 
Note that rebuilding the DLL using dynamic runtime linking is not available since we are using the FIPS DLL."
        -  http://www.codeproject.com/Articles/16388/Compiling-and-Integrating-Crypto-into-the-Microsof
   
"Hoping no runtime issues occur"  is not genuinely acceptable.

That web page listed a couple of more tricks to try, 
but I've already tried the separate library and DLL trick suggested by wei 
(here http://groups.google.com/group/cryptopp-users/msg/6373d2c85e7b0e8d and in the readme) 
and that didn't seem to work either.

Another possibility is the Cryptopp web page mentions the FIPS DLL is only compatable with VS2005.
The date of that note and some of the surrounding text left me with the impression he was talking 
about it not being compatible with earlier versions of Visual C++.
My experiance is that I've never noticed compatability problems with _newer_ versions, 
but perhaps I've just been lucky in the past and esapi needs 
a 2005 project/build in order to use the FIPS DLL.

But even after backing up a version and building this solution for VS2005,
I continue to have no luck building esapi using the FIPS DLL.

I did finally work out solution settings that allow me to build everything
and execute the unit tests using VS2005, by having everything build as static libraries.

Unfortunately I wasn't able to do this without making modifications to 
supplied libraires and source code.

I can't believe this is that big of a problem, 
I have got to be looking right past a very obvious "oops",
but then all solutions are obvious once you find them. 

 - jAHOLMES (starfyr@jholmesassociates.com)  2012.02.08

=============================================================
These are the procedures I used to install and use 
Crypto++ 5.3.0 as a static Lib
=============================================================
---
---

Setting up Crypto++ 5.3.0 for use with esapi-cpp

---
---

To build the missing library we first need to get the solution 
file and project files to open correctly.
As supplied they DO NOT WORK.  
The file locations specified in the project file do not match 
the names and locations of the actual directories.

The Cryptopp 530 zip file comes with a Visual Studio 2005 solution file 
(not 2003 as indicated in the file Readme.txt).
If you open the solution file supplied, 
you will get error reports, because it can't find one of the projects.
If you try to open or build any of the projects in the solution, 
it will be unable to find the header files.

This was my out-of-the box experiance.
If your experiance is different, hopefully the instructions, 
notes and readme files mentioned above can get you to a working 
build using the FIPS library.

To allow the supplied solution to open all the projects 
and find all the include files
perform the following steps:

Rename
	C:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\Source
to
	C:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\cryptopp

Move all the files (126) from
	C:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\Include
to
	C:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\cryptopp

Move all the files (2) from
	C:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\DllTest
to
	C:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\cryptopp
	
Based on the directories where you actually installed the crypto library
you need to define two environment variables.

CRYPTOPP=C:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530
CRYPTOPP_VERSION=530

Startmenu->Computer, right click properties, 
click Advanced System Settings, click Environment Variables...

will take you to the screen where you can define and enter these values.
Remember you must restart any command windows or Visual Studio before 
these new values will take effect.

From the Start Menu, find Visual Studio 2005, "Run As Administrator" 
(see the note that appears when Visual Studio 2005 starts)
Once VS2005 is running, File->Open->Solution,  
navigate to the 
	C:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\cryptopp 
directory and select cryptest.sln

Since we know stuff had to move around take a moment to spot check by 
opening a source and header file in each project to make sure they can be found.

If you build now, it will fail because the library search paths are not set correctly.

I fiddled with a copy until I got it to compile,
but that involved changing a lot of build and configuration settings.

For our puroses here, 
I'm not going to try to fix the existing build configurations;
I've created a new solution file in the esapi tree that will 
build the libraries we need locally.

Unfortunately the default esapi build configuration 
and the cryptopp setting are not fully compatible.
So even with our own project, there are further changes to be made.

Most of the changes are related to esapi using UNICODE.

I can't adequately explain the problem in integer.cpp,
the typedef for AllocatorBase<T>::pointer should clearly equate to T*,
but either the template interpreter, or the name mangler, 
is doing something unexpected.

-------------------------------
CRYPTO++  FILE  EDITS
-------------------------------

EDIT FILE 

c:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\cryptopp\integer.cpp

Line 55:
replace
CPP_TYPENAME AllocatorBase<T>::pointer AlignedAllocator<T>::allocate(size_type n, const void *)
with
#if 0 // AllocatorBase<T>::pointer broken???
CPP_TYPENAME AllocatorBase<T>::pointer AlignedAllocator<T>::allocate(size_type n, const void *)
#else
CPP_TYPENAME T* AlignedAllocator<T>::allocate(size_type n, const void *)
#endif

[This one bothers me, I can't see any reason why it fails]

---

EDIT FILE

c:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\cryptopp\fipstest.cpp

Lines 306
replace
	OutputDebugString(L"Crypto++ DLL integrity check failed. Cannot open file for reading.");
with
#ifdef _UNICODE
		OutputDebugString(L"Crypto++ DLL integrity check failed. Cannot open file for reading.");
#else
		OutputDebugString("Crypto++ DLL integrity check failed. Cannot open file for reading.");
#endif

	
Line 400  replace	
	OutputDebugString("In memory integrity check failed. This may be caused by debug breakpoints or DLL relocation.\n");
with
#ifdef _UNICODE
		OutputDebugString(L"In memory integrity check failed. This may be caused by debug breakpoints or DLL relocation.\n");
#else
		OutputDebugString("In memory integrity check failed. This may be caused by debug breakpoints or DLL relocation.\n");
#endif  // _UNICODE
	
	
Line 419 	
replace
	OutputDebugString((("Crypto++ DLL integrity check failed. Actual MAC is: " + hexMac) + "\n").c_str());
with
#ifdef _UNICODE
    std::string temp = (("Crypto++ DLL integrity check failed. Actual MAC is: " + hexMac) + "\n");
    size_t osize = strlen( temp.c_str() ) + 1;
    size_t nsize = 0;
    wchar_t wTemp[ 256 ];
    mbstowcs_s( &nsize, wTemp, osize, temp.c_str(), _TRUNCATE );
	OutputDebugString(wTemp);
#else
	OutputDebugString((("Crypto++ DLL integrity check failed. Actual MAC is: " + hexMac) + "\n").c_str());
#endif  // _UNICODE

---

EDIT FILE

c:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\cryptopp\dll.cpp

Lines 99 - 102
replace
	hModule = GetModuleHandle("msvcrtd");
	if (!hModule)
		hModule = GetModuleHandle("msvcrt");
with
#ifdef _UNICODE
	hModule = GetModuleHandle(L"msvcrtd");
	if (!hModule)
		hModule = GetModuleHandle(L"msvcrt");
#else
	hModule = GetModuleHandle("msvcrtd");
	if (!hModule)
		hModule = GetModuleHandle("msvcrt");
#endif // _UNICODE
	
Lines 109
replace
	OutputDebugString("Crypto++ was not able to obtain new and delete function pointers.\n");
with	
#ifdef _UNICODE
	OutputDebugString(L"Crypto++ was not able to obtain new and delete function pointers.\n");
#else
	OutputDebugString("Crypto++ was not able to obtain new and delete function pointers.\n");
#endif  // _UNICODE


---
---

You can make the above edits by hand, or 
I have saved copies of these files with the required modifications to
$(owasp-esapi-cplusplus)\esapi_C530_VS8\cryptopp_replacements
which would need to be copied into the directory
	C:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530\cryptopp
overwriting the original versions.

---
---

The solution file to build the version of the crypto library we need is found at
	$(owasp-esapi-cplusplus)\esapi_C530_VS8\crypto530_VS8.sln

To use this solution file you must go to the windows 
Start menu, find the  Microsoft Visual Studio 2005 menu item and "Run as Administrator"
(see the note displayed when Visual Studio Starts for an explaination).

After loading the Solution, assuming all the required environment variables are set, 
and files have been installed and unzipped in the correct places as described in the foregoing,
you should be able to build the crypto++ libraries 

using the menu File->Open->Project/Solution, navigate to 
	$(owasp-esapi-cplusplus)\esapi_C530_VS8\crypto530_VS8.sln
and open the solution.

After the solution finishes loading using the menu
Build->BatchBuild;  click select all,  click Rebuild All

The build should begin.
Unless somethign has gone wrong, it should build with no fatal errors.
There are a number of harmless warnings.

At this point I get a successful build of both libraries.

The output can be found in the directory

	$(owasp-esapi-cplusplus)\esapi_C530_VS8\win32\debug-static
	$(owasp-esapi-cplusplus)\esapi_C530_VS8\x64\debug-static

[as of 2012.02.08,  I only build static .lib]