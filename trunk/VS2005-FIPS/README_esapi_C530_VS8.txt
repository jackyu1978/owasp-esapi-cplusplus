==========================================================================
esapi-cplusplus Crypto++ 5.3.0 Solution for Visual Studio 2005
==========================================================================

This file documents information pertaining to the solution 
file for building the esapi-cplusplus library and unit tests for use with 
the Crypto++ library using Visual Studio 2005.

Other important documentation files are 
	README_esapi_BOOST.txt
	README_esapi_CYRPTO_VS8.txt
	

The solution file is can be found at 
	$(owasp-esapi-cplusplus)\esapi_C530_VS8\esapi_C530_VS8.sln
	
To use this solution you must define the environment variables 
for the BOOST and CRYPTO++ libraries.  See those documents for details but briefly:

Based on the directories where you actually installed the crypto library
you need to define two environment variables.

BOOST_ROOT=C:\SoftwareDevelopment\ThirdPartyLibs\boost_1_47_0
CRYPTOPP=C:\SoftwareDevelopment\ThirdPartyLibs\cryptopp530
CRYPTOPP_VERSION=530

Startmenu->Computer, right click properties, 
click Advanced System Settings, click Environment Variables...

will take you to the screen where you can define and enter these values.
Remember you must restart any command windows or Visual Studio before 
these new values will take effect.

You need to follow the instructions in the BOOST Document mentioned 
above to use the Boost tools to build the required library files.

You need to follow the instruction in the CRYPTO Document mentioned
above to use our solution file 	
	$(owasp-esapi-cplusplus)\esapi_C530_VS8\crypto530_VS8.sln
to build the required Crypto++ libraries.


The following files are intentionally excluded from the build process:

	q:\owasp-esapi-cplusplus\src\crypto\RandomPool-Starnix.cpp
	q:\owasp-esapi-cplusplus\src\util\TextConvert-Starnix.cpp

Are omitted because they apply to *nix implementations 
of the esapi-cplusplus library, and are not used under windows.

	q:\owasp-esapi-cplusplus\src\reference\validation\StringValidationRule.cpp
	q:\owasp-esapi-cplusplus\test\reference\validation\StringValidationRuleTest.cpp
	
Are omitted because 
1) they were omitted in an earlier version of a Visual Studio solution file,
2) they do not build correctly at this time.  
I've done no investigation into the reasons for the ommission.

If the files have all been checked-out, installed and unzipped in the correct 
locations according to the foregoing instructions, and the environment variables 
are set correctly, the solution file 
		$(owasp-esapi-cplusplus)\esapi_C530_VS8\esapi_C530_VS8.sln
should build correctly.

Using the start menu, find the menu entry for 
Microsoft Visual Studio 2005, right click and "Run as Administrator"
(see the message when VS2005 starts up for an explination).

Once visual Studio is running 

using the menu File->Open->Project/Solution, navigate to 
		$(owasp-esapi-cplusplus)\esapi_C530_VS8\esapi_C530_VS8.sln
and open the solution.

After the solution finishes loading using the menu
Build->BatchBuild;  click select all,  click Rebuild All

The build should begin.
Unless somethign has gone wrong, it should build with no fatal errors.
There are a number of harmless warnings.

At this point I get a successful build of both the esapi-lib 
library esapi-lib.lib and the test executable esapi-test.exe


The output can be found in the directory

	$(owasp-esapi-cplusplus)\esapi_C530_VS8\win32\debug-static
	$(owasp-esapi-cplusplus)\esapi_C530_VS8\x64\debug-static

[as of 2012.02.08,  I only build static .lib]

[as of 2012.02.09  The test executable builds and runs, but many tests fail;
49 failures of 251 tests, plus some memory leaks.]