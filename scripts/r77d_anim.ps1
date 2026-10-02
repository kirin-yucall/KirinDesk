#
# Usage (run in background, Stop-Process after bench):
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\r77d_anim.ps1 -Mode rect
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\r77d_anim.ps1 -Mode dot
#
# Modes:
#   rect - large motion (160x120 red block, ~30fps): activity >= motion_ratio
#          -> governor motion tier (60fps). Measures "normal dynamic content".
#   dot  - cursor-sized change (24x24 red dot, ~30fps): 1-2 tiles changed
#          per frame -> reproduces the client-side "screen lags behind mouse"
#          scenario (governor static/low tier boundary behavior).
#
# TopMost 320x240 @ (120,120); 16ms timer + Invalidate (DXGI desktop
# duplication produces frames at screen-change rate, in sync with this).
param(
    [ValidateSet("rect", "dot")]
    [string]$Mode = "rect"
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:state = @{ x = 10.0; y = 10.0; dx = 3.0; dy = 2.0 }

$f = New-Object System.Windows.Forms.Form
$f.Width = 320
$f.Height = 240
$f.StartPosition = 'Manual'
$f.Location = New-Object System.Drawing.Point(120, 120)
$f.TopMost = $true
$f.BackColor = [System.Drawing.Color]::Black

$onPaint = {
    param($sender, $e)
    $g = $e.Graphics
    $g.Clear([System.Drawing.Color]::Black)
    $s = $script:state
    if ($Mode -eq "dot") {
        $g.FillEllipse([System.Drawing.Brushes]::Red, $s.x, $s.y, 24, 24)
    } else {
        $g.FillRectangle([System.Drawing.Brushes]::Red, $s.x, $s.y, 160, 120)
    }
    $g.DrawRectangle([System.Drawing.Pens]::White, 0, 0, 296, 190)
}
$f.Add_Paint($onPaint)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 16
$timer.Add_Tick({
    $s = $script:state
    $s.x += $s.dx
    $s.y += $s.dy
    if ($Mode -eq "dot") {
        if ($s.x -gt 270) { $s.dx = -3.0 }
        if ($s.x -lt 2)   { $s.dx = 3.0 }
        if ($s.y -gt 160) { $s.dy = -2.0 }
        if ($s.y -lt 2)   { $s.dy = 2.0 }
    } else {
        if ($s.x -gt 130) { $s.dx = -3.0 }
        if ($s.x -lt 2)   { $s.dx = 3.0 }
        if ($s.y -gt 65)  { $s.dy = -2.0 }
        if ($s.y -lt 2)   { $s.dy = 2.0 }
    }
    $f.Invalidate()
})
$timer.Start()

[System.Windows.Forms.Application]::Run($f)
