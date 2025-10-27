# Start local CIS Aurora server (PowerShell)
param([string]$Analyzer="python anty_scam.py {address}")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path "venv")) {
  py -m venv venv
}
.\venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
$env:ANALYZER_CMD = $Analyzer
py serwer.py
