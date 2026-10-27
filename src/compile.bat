cl -EHsc -Ox omtfs.cpp -I "...\winfsp\inc" -c

link omtfs.obj /OUT:omtfs.exe /LIBPATH:"C:\Program Files (x86)\WinFsp\lib" ^
  winfsp-x64.lib advapi32.lib bcrypt.lib delayimp.lib shlwapi.lib ^
  /DELAYLOAD:winfsp-x64.dll
rm *.obj
rm log

