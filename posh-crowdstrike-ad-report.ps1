#########################################################################################
# 
# POSH script to compare AD computer objects to Crowdstrike API output and report any AD 
# computers thatdo not have CrowdStrike Falkcon installed.
# 
# 
# 
#########################################################################################

# Variables

$dc = 'dcprdc1001' # PROD
# $Adcreds = Get-Credential  -Message "Enter AD credentials:" 


# Get all PC objects with all properties
# may need to filer

get-adcomputer -server $dc -filter * -properties * | Select-Object name


# Crowdstrike API


# API connection example to pull token and import PSFalcon (Crowdstrike Powershell module)

#Requires -Version 5.1
<# using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
[CmdletBinding()]
param(
    [Parameter(Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$ClientId,
    [Parameter(Mandatory,Position=2)]
    [ValidatePattern('^\w{40}$')]
    [string]$ClientSecret,
    [Parameter(Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$MemberCid,
    [Parameter(Position=4)]
    [ValidateSet('us-1','us-2','us-gov-1','eu-1')]
    [string]$Cloud
)
begin {
    $Token = @{}
    @('ClientId','ClientSecret','Cloud','MemberCid').foreach{
        if ($PSBoundParameters.$_) { $Token[$_] = $PSBoundParameters.$_ }
    }
}
process {
    try {
        Request-FalconToken @Token
        if ((Test-FalconToken).Token -eq $true) {
            # Insert code to run here
        }
    } catch {
        throw $_
    } finally {
        if ((Test-FalconToken).Token -eq $true) { Revoke-FalconToken }
    }
}
 #>


# get host names (Windows only)

Get-FalconHost -Filter "platform_name:'Windows'" [-Detailed] [-All]