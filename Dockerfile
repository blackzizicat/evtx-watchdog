
FROM mcr.microsoft.com/windows-cssc/python:3.11-servercore-ltsc2019

SHELL ["powershell", "-Command"]

RUN $csUrl = 'https://github.com/WithSecureLabs/chainsaw/releases/download/v2.13.1/chainsaw_x86_64-pc-windows-msvc.zip'; \
    $csZip = 'C:\\chainsaw.zip'; \
    Invoke-WebRequest -UseBasicParsing -Uri $csUrl -OutFile $csZip; \
    Expand-Archive -Path $csZip -DestinationPath 'C:\\'; \
    Remove-Item $csZip -Force
