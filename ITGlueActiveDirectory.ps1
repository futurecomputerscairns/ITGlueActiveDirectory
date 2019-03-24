Param (
       [string]$organisation = "",
       [string]$key = ""
       )

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


$assettypeID = 72196

$ITGbaseURI = "https://api.itglue.com"

 
$headers = @{
    "x-api-key" = $key
}

Import-Module C:\temp\itglue\modules\itgluepowershell\ITGlueAPI.psd1 -Force
Add-ITGlueAPIKey -Api_Key $key
Add-ITGlueBaseURI -base_uri $ITGbaseURI

function CreateITGItem ($resource, $body) {
    $item = Invoke-RestMethod -Method POST -ContentType application/vnd.api+json -Uri $ITGbaseURI/$resource -Body $body -Headers $headers
    #return $item
}

function Build365TenantAsset ($tenantInfo) {
    
    $body = @{
        data = @{
            type       = "flexible-assets"
            attributes = @{
                "organization-id"        = $ITGlueOrganisation
                "flexible-asset-type-id" = $assettypeID
                traits                   = @{
                    "ad-full-name"      = $tenantInfo.ADFullName
                    "ad-short-name"        = $tenantInfo.ADShortName
                    "ad-servers"   = $tenantInfo.ADServers
                    "dns-servers" = $tenantInfo.DNSServers
                    "dhcp-servers"         = $tenantInfo.DHCPServers
                    "ad-level"   = $tenantInfo.ADLevel
                    "primary-domain-controller"   = $tenantInfo.PDC
                    "global-catalog-server-s"   = $tenantInfo.GCs
                    "domain-admins"   = $tenantInfo.DomainAdmins
                    "ou-naming-conventions"   = $tenantInfo.ou
                    "schema-master"   = $tenantInfo.schemamaster
                    #"read-only-domain-controllers"   = $tenantInfo.rodcs
                   
                }
            }
        }
    }
    
    $tenantAsset = $body | ConvertTo-Json -Depth 10
    return $tenantAsset
}

function CreateITGItem ($resource, $body) {
    $item = Invoke-RestMethod -Method POST -ContentType application/vnd.api+json -Uri $ITGbaseURI/$resource -Body $body -Headers $headers
    #return $item
}

function Recurse-OU ([string]$dn, $level = 1)
{
    if ($level -eq 1) { $dn }
    Get-ADOrganizationalUnit -filter * -SearchBase $dn -SearchScope OneLevel | 
        Sort-Object -Property distinguishedName | 
        ForEach-Object {
            $components = ($_.distinguishedname).split(',')
            "$('--' * $level) $($components[0])"
            Recurse-OU -dn $_.distinguishedname -level ($level+1)
        }
}

function Get-ITGlueID($ServerName){

(Get-ITGlueConfigurations -filter_name $ServerName).data.id 

}

Write-Host Attempting match of ITGlue Company using name $organisation -ForegroundColor Green

$attempted_match = Get-ITGlueOrganizations -filter_name "$organisation"

if($attempted_match.data[0].attributes.name -eq $organisation) {
            Write-Host "Auto-match of ITGlue company successful." -ForegroundColor Green

            $ITGlueOrganisation = $attempted_match.data.id
}
            else {
            Write-Host "No auto-match was found. Please pass the exact name in ITGlue to -organization <string>" -ForegroundColor Red
            Exit
            }


#
# Remove Existing
#

$existing = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $assettypeID -filter_organization_id $ITGlueOrganisation
if ($existing -ne $null){
$existing.data | % {

Write-Host Removing existing Active Directory from ITGlue

Remove-ITGlueFlexibleAssets -id $_.id -Confirm:$false}

}

$array = @()
$adservers_array = @()
$dnsservers_array = @()
$DHCPServers_array = @()
$GCS_Array = @()
$RODC_array = @()
$domain = Get-ADDomain
$domain2 = Get-ADForest
$domainlong = $domain.DNSRoot
$domainshort = $domain.NetBIOSName
$ADServers = $domain.ReplicaDirectoryServers

foreach ($adserver in $adservers){
$adserver2 = ($adserver).Replace(("." + "$domainlong"),"")
$ADS_ID = (Get-ITGlueID -ServerName $adserver2)
$ADServers_Array += $ADS_ID
}

$dnsServers = (Resolve-DnsName $domainlong -type ns | ? {$_.type -eq "A"} | select name, IP4Address).name

foreach ($dnsserver in $dnsservers){
$dnsserver2 = ($dnsserver).Replace(("." + "$domainlong"),"")
$DNS_ID = (Get-ITGlueID -ServerName $dnsserver2)
$DNSServers_Array += $DNS_ID
}

$DHCPServers = (Get-DHCPServerinDC).DNSName

foreach ($dhcpserver in $dhcpservers){
$dhcpserver2 = ($dhcpserver).Replace(("." + "$domainlong"),"")
$DHCP_ID = (Get-ITGlueID -ServerName $dhcpserver2)
$DHCPServers_Array += $DHCP_ID
}

$ADLevel = $domain.DomainMode
if ($ADLevel -match "Windows2008Domain"){
    $ADLevel = "2008"}
    elseif ($ADLevel -match "Windows2008R2Domain"){
    $ADLevel = "2008R2"}
    elseif ($ADLevel -match "Windows2010Domain"){
    $ADLevel = "2010"}
    elseif ($ADLevel -match "Windows2012Domain"){
    $ADLevel = "2012"}
    elseif ($ADLevel -match "Windows2003Domain"){
    $ADLevel = "2003"}
$PDC = $Domain.PDCEmulator
$PDC = ($PDC).Replace(("." + "$domainlong"),"")
$PDC = Get-ITGlueID -ServerName $PDC
$SchemaMaster = $domain2.SchemaMaster
$SchemaMaster = ($SchemaMaster).Replace(("." + "$domainlong"),"")
$SchemaMaster = Get-ITGlueID -ServerName $SchemaMaster
 
$GCs = $domain2.GlobalCatalogs

foreach ($gc in $gcs){
$gc2 = ($gc).Replace(("." + "$domainlong"),"")
$GC_ID = (Get-ITGlueID -ServerName $gc2)
$GCS_Array += $GC_ID
}

$RODCs = Get-ADDomainController -Filter * | Where-Object {$_.IsReadOnly -eq $true}

foreach ($rodc in $rodcs){
$rodc2 = ($rodc).Replace(("." + "$domainlong"),"")
$RODC_ID = (Get-ITGlueID -ServerName $rodc2)
$RODC_Array += $RODC_ID
}
if ($RODC_array -eq $null){
$RODC_array = @()
}

$domainadmins = ((Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select name).name) -join ", "
$ou = Recurse-OU -dn (Get-ADDomain).DistinguishedName
$ou = $ou -join "<br>" | Out-String

$object = New-Object psobject
$object | Add-Member -MemberType NoteProperty -Name ADFullName -Value $domainlong
$object | Add-Member -MemberType NoteProperty -Name ADShortName -Value $domainshort
$object | Add-Member -MemberType NoteProperty -Name ADServers -Value $adservers_array
$object | Add-Member -MemberType NoteProperty -Name DNSServers -Value $dnsservers_array
$object | Add-Member -MemberType NoteProperty -Name DHCPServers -Value $dhcpservers_array
$object | Add-Member -MemberType NoteProperty -Name ADLevel -Value $adlevel
$object | Add-Member -MemberType NoteProperty -Name PDC -Value $pdc
$object | Add-Member -MemberType NoteProperty -Name SchemaMaster -Value $schemamaster
$object | Add-Member -MemberType NoteProperty -Name GCs -Value $gcs_array
$object | Add-Member -MemberType NoteProperty -Name DomainAdmins -Value $domainadmins
$object | Add-Member -MemberType NoteProperty -Name OU -Value $ou
$array += $object

$body = Build365TenantAsset -tenantInfo $array
CreateITGItem -resource flexible_assets -body $body
