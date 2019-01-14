## IMPORTANT: Requires Powershell V3+
if ($PSVersionTable.PSVersion.Major -lt 3) {
	echo "Get Powershell 3 here: http://www.microsoft.com/en-us/download/details.aspx?id=34595 "
	throw "Powershell version 3 or greater required for this script"
}

$GLOBAL_PASS = read-host "Enter password for the certificates" 
$GLOBAL_PASS_SS = (ConvertTo-SecureString "$GLOBAL_PASS" -AsPlainText -Force)

. ./src/New-SelfSignedCertificateEx.ps1

# Serialise a certificate file to a hex string
function SerialiseCert ([string]$cerFilename, [string]$pwd, [string]$destFile) {
	$cmdBuilder = New-Object -TypeName System.Text.StringBuilder

	$dir = pwd
	echo "Serialising $dir\$cerFilename to $destFile"
	if ($pwd) {
		$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$dir\$cerFilename", $pwd)
	} else {
		$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$dir\$cerFilename")
	}

	$cmdBuilder = $cmdBuilder.AppendFormat("0x{0}", $certificate.GetRawCertDataString())
	echo $cmdBuilder.ToString() > "$dir\$destFile"
}

# Extract data from a pfx file to various formats used in the wild
function Extract($src) {
	$dir = pwd

    # Make `.cer` public-only file from the pfx, and a public-only pem file
	./bin/openssl.exe pkcs12 -in "$dir\$src" -out "$dir\$src.public.pem" -nokeys -passin "pass:$GLOBAL_PASS"
	./bin/openssl.exe x509 -in "$dir\$src.public.pem" -out "$dir\$src.cer" -outform der -passin "pass:$GLOBAL_PASS"
	
    # Make a full pem file (for AWS & docker) from the pfx
    ./bin/openssl.exe pkcs12 -in "$dir\$src" -out "$dir\$src.pem" -nodes -clcerts -passin "pass:$GLOBAL_PASS"
}

# Generate a site-specific certificate
function GenSite($site, $auth) {
	$dir = pwd
	
	New-SelfsignedCertificateEx -Subject "CN=$site" -Authority "$auth" -SAN "$site" -Path "$site.pfx" -EKU "1.3.6.1.5.5.7.3.1", "Client authentication" -KeyUsage "KeyEncipherment, DigitalSignature, KeyCertSign, DataEncipherment" -AllowSMIME -Exportable -SerialNumber "01a4ff2" -KeySpec "Exchange" -Password $GLOBAL_PASS_SS
	Extract "$site.pfx"
	SerialiseCert "$site.pfx.cer" -destFile "$site.cert.txt"
}

# Adds PFX files to the local machine's trusted certs store.
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

# Name of a authority cert to use (or create and use)
$rootFile = "DevRootCA"

# Uncomment this bit to get a root certificate
# You should only do this once
    ## Make the certificate:
    New-SelfsignedCertificateEx -Subject "CN=DEVELOPMENT Root CA, OU=Sandbox" -Path "$rootFile.pfx" -IsCA $true -ProviderName "Microsoft Software Key Storage Provider" -Exportable -Password $GLOBAL_PASS_SS
    ## Extract .cer and .pem files from the .pfx:
    Extract "$rootFile.pfx"
    ## Add the .pfx to the local machine's trust store:
    #Import-PfxCertificate -certPath "$rootFile.pfx.cer" -certRootStore "LocalMachine" -certStore "root" -pfxPass $GLOBAL_PASS_SS

# Make certs for sites
# Requires a root certificate either a proper trusted cert or a test self-sign from above
    ## Make a cert for localhost
    GenSite "localhost" "$rootFile.pfx.cer"
    ## Make a cert for each site
    #GenSite "mysiet.cloudapp.net" "$rootFile.pfx.cer"
    #GenSite "other.example.net" "$rootFile.pfx.cer"
    ## Turn the pfx file into a byte string, if required
    #SerialiseCert "core.example.com.pfx" -pwd $GLOBAL_PASS -destFile "core.example.pfx.txt"




