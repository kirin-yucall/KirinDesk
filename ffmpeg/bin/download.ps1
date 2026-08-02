# FFmpeg 8.1.2 full shared build (official release, not BtbN master)
# DLL versions: avcodec-62 / avutil-60 / swscale-9
$base = "https://github.com/yu-ffmpeg/ffmpeg/releases/download/n8.1.2"
$url = "https://github.com/GyanD/codexffmpeg/releases/download/8.1.2/ffmpeg-8.1.2-full_build-shared.zip"
$out = "C:\Users\yu\旧e\kirin_rd\KirinDesk\ffmpeg\bin\ffmpeg-shared.zip"
Write-Host "Downloading FFmpeg 8.1.2 shared build..."
Write-Host "URL: $url"
Write-Host "Output: $out"
# Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
Write-Host "After download, unzip and place in ffmpeg/ffmpeg-8.1.2-full_build-shared/"
Write-Host "DLL files needed: avcodec-62.dll, avutil-60.dll, swscale-9.dll"
