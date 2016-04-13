# Create test files on C:\DemoSite
New-Item C:\DemoSite -type Directory
New-Item C:\DemoSite\DemoApp -type Directory
New-Item C:\DemoSite\DemoVirtualDir1 -type Directory
New-Item C:\DemoSite\DemoVirtualDir2 -type Directory 

Set-Content C:\DemoSite\Default.htm "DemoSite Default Page"
Set-Content C:\DemoSite\DemoApp\Default.htm "DemoSite\DemoApp Default Page"
Set-Content C:\DemoSite\DemoVirtualDir1\Default.htm "DemoSite\DemoVirtualDir1 Default Page"
Set-Content C:\DemoSite\DemoVirtualDir2\Default.htm "DemoSite\DemoApp\DemoVirtualDir2 Default Page"