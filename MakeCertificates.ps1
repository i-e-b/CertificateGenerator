## IMPORTANT: Requires Powershell V3+
if ($PSVersionTable.PSVersion.Major -lt 3) {
	echo "Get Powershell 3 here: http://www.microsoft.com/en-us/download/details.aspx?id=34595 "
	throw "Powershell version 3 or greater required for this script"
}

$GLOBAL_PASS = read-host "Enter password for the certificates" 
$GLOBAL_PASS_SS = (ConvertTo-SecureString "$GLOBAL_PASS" -AsPlainText -Force)

. ./src/New-SelfSignedCertificateEx.ps1

function GenSite($site, $auth) {
	New-SelfsignedCertificateEx -Subject "CN=$site" -Authority "$auth" -SAN "$site" -Path "$site.pfx" -EKU "1.3.6.1.5.5.7.3.1", "Client authentication" -KeyUsage "KeyEncipherment, DigitalSignature, KeyCertSign, DataEncipherment" -AllowSMIME -Exportable -SerialNumber "01a4ff2" -KeySpec "Signature" -Password $GLOBAL_PASS_SS
	Extract "$site.pfx"
}

function Extract($src) {
	$dir = pwd
	./bin/openssl.exe pkcs12 -in "$dir\$src" -nocerts -nodes -out pk.pem -passin "pass:$GLOBAL_PASS"
	./bin/pvk -in pk.pem -topvk -out "$dir\$src.pvk"
	rm pk.pem

	./bin/openssl.exe pkcs12 -in "$dir\$src" -out pub.pem -nodes -passin "pass:$GLOBAL_PASS"
	./bin/openssl.exe x509 -in pub.pem -out "$dir\$src.cer" -outform der -passin "pass:$GLOBAL_PASS"
	rm pub.pem
}

function Import-PfxCertificate {
	param([String]$certPath,[String]$certRootStore = "CurrentUser",[String]$certStore = "My",$pfxPass = $null)
	$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2
	
	if ($pfxPass -eq $null) {$pfxPass = read-host "Enter the pfx password" -assecurestring}
	
	$fullpath = Resolve-Path $certPath
	$pfx.import($fullpath,$pfxPass,"Exportable,PersistKeySet")
	
	$store = new-object System.Security.Cryptography.X509Certificates.X509Store($certStore,$certRootStore)
	$store.open("MaxAllowed")
	$store.add($pfx)
	$store.close()
}

$rootFile = "DevRootCA"

New-SelfsignedCertificateEx -Subject "CN=DEVELOPMENT Root CA, OU=Sandbox" -Path "$rootFile.pfx" -IsCA $true -ProviderName "Microsoft Software Key Storage Provider" -Exportable -Password $GLOBAL_PASS_SS
Extract "$rootFile.pfx"
Import-PfxCertificate -certPath "$rootFile.pfx.cer" -certRootStore "LocalMachine" -certStore "root" -pfxPass $GLOBAL_PASS_SS

GenSite "www.example.com" "$rootFile.pfx.cer"
GenSite "www.example.net" "$rootFile.pfx.cer"
