
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

(Get-ITGlueConfigurations -filter_name $_.ServerName).data.'id' | Select-Object -First 1

}

$object = @()
$domain = Get-ADDomain
$domain2 = Get-ADForest
$domainlong = $domain.DNSRoot
$domainshort = $domain.NetBIOSName
$ADServers = $domain.ReplicaDirectoryServers
$dnsServers = (Resolve-DnsName $domainlong -type ns | ? {$_.type -eq "A"} | select name, IP4Address).name
$DHCPServers = (Get-DHCPServerinDC).DNSName
$ADLevel = $domain.DomainMode
$PDC = $Domain.PDCEmulator
$SchemaMaster = $domain2.SchemaMaster
$GCs = $domain2.GlobalCatalogs
$RODC = Get-ADDomainController -Filter * | Where-Object {$_.IsReadOnly -eq $true}
$domainadmins = (Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select name).name
$ou = Recurse-OU -dn (Get-ADDomain).DistinguishedName


 

$object = New-Object psobject
$object | Add-Member -MemberType NoteProperty -Name ADFullName -Value $domainlong
$object | Add-Member -MemberType NoteProperty -Name ADShortName -Value $domainshort
$object | Add-Member -MemberType NoteProperty -Name ADServers -Value $domainlong
$object | Add-Member -MemberType NoteProperty -Name ADFullName -Value $domainlong
$object | Add-Member -MemberType NoteProperty -Name ADFullName -Value $domainlong
$object | Add-Member -MemberType NoteProperty -Name ADFullName -Value $domainlong
$object | Add-Member -MemberType NoteProperty -Name ADFullName -Value $domainlong
$object | Add-Member -MemberType NoteProperty -Name ADFullName -Value $domainlong
$object | Add-Member -MemberType NoteProperty -Name ADFullName -Value $domainlong
$object | Add-Member -MemberType NoteProperty -Name ADFullName -Value $domainlong
$object | Add-Member -MemberType NoteProperty -Name ADFullName -Value $domainlong