param([string]$cerFilename, [string]$pwd)

$cmdBuilder = New-Object -TypeName System.Text.StringBuilder

if ($pwd) {
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerFilename, $pwd)
} else {
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerFilename)
}

$cmdBuilder = $cmdBuilder.AppendFormat("0x{0}", $certificate.GetRawCertDataString())

echo $cmdBuilder.ToString()
