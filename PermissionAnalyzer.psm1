#Requires -Version 7.0

# Dot-source all private functions
foreach ($file in (Get-ChildItem -Path "$PSScriptRoot/Private" -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
    . $file.FullName
}

# Dot-source all public functions
foreach ($file in (Get-ChildItem -Path "$PSScriptRoot/Public" -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
    . $file.FullName
}
