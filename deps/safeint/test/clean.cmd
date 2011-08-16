rmdir /s /q "%~dp0\SafeIntTest"
rmdir /s /q "%~dp0\TestMain"

attrib -r -a -s -h "%~dp0\*.ncb"
attrib -r -a -s -h "%~dp0\*.suo"

erase /f /s "%~dp0\*.ncb"
erase /f /s "%~dp0\*.plg"
erase /f /s "%~dp0\*.opt"
erase /f /s "%~dp0\*.suo"
erase /f /s "%~dp0\*.user"