rmdir /s /q "%~dp0\Debug"
rmdir /s /q "%~dp0\Release"
rmdir /s /q "%~dp0\ipch"

attrib -r -a -s -h "%~dp0\*.ncb"
attrib -r -a -s -h "%~dp0\*.suo"

erase /f /s "%~dp0\*.ncb"
erase /f /s "%~dp0\*.plg"
erase /f /s "%~dp0\*.opt"
erase /f /s "%~dp0\*.suo"

erase /f /s "%~dp0\*.user"
erase /f /s "%~dp0\*.aps"

erase /f /s "%~dp0\Esapi-Windows\*.user"
erase /f /s "%~dp0\Esapi-Windows\*.aps"
