<#
    Part of SharpJS.Azure - Random Helpful PowerShell Cmdlets for Azure
    Copyright (C) 2017 Jeffrey Sharp
    https://github.com/sharpjs/SharpJS.Azure

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
#>

# Pattern for end-of-line
$EolRe = [regex] '\r?\n'

# (Lazy) pattern for IP or CIDR format
$AddressRe = [regex] '\d{1,3}(?:\.\d{1,3}){3}(?:/\d\d?)?'

function Merge-AzureRmNetworkSecuritySourceIpList {
    <#
    .SYNOPSIS
        Merges rules allowing a list of source addresses into a network security group's inbound rules set.
    #>
    [CmdletBinding(DefaultParameterSetName="AllPorts")]
    param (
        [Parameter(Mandatory, Position=0)]
        [string] $ResourceGroupName,

        [Parameter(Mandatory, Position=1)]
        [string] $NetworkSecurityGroupName,

        [Parameter(Mandatory, Position=2, ValueFromPipeline)]
        [string[]] $SourceAddresses,

        [ValidateSet("*", "Tcp", "Udp")]
        [string] $Protocol = "*",

        [Parameter(Mandatory, ParameterSetName="SpecificPorts")]
        [string] $DestinationPortRange = "*",

        [Parameter(Mandatory, ParameterSetName="SpecificPorts")]
        [string] $ServiceName = "all",

        [Parameter()]
        [int] $MinimumPriority = 10000
    )

    begin {
        $Group = Get-AzureRmNetworkSecurityGroup `
            -Name              $NetworkSecurityGroupName `
            -ResourceGroupName $ResourceGroupName

        $SourceName = ""
        $Ordinal    = 0
        $Priority   = $MinimumPriority
    }

    process {
        foreach ($Line in $SourceAddresses -split '\r?\n') {
            # Ignore empty lines
            $Line = $Line.Trim()
            if (!$Line) { continue }

            # Is it an IP address?
            if ($Line -match $AddressRe) {
                $Address = $Line
                Write-Host "allow-$ServiceName-from-$SourceName-$Ordinal" `
                # $Group | Add-AzureRmNetworkSecurityRuleConfig `
                #     -Direction                 Inbound `
                #     -Protocol                  $Protocol `
                #     -SourceAddressPrefix       $Address `
                #     -SourcePortRange           * `
                #     -DestinationAddressPrefix  * `
                #     -DestinationPortRange      $DestinationPortRange `
                #     -Access                    Allow `
                #     -Name                      "allow-$ServiceName-from-$SourceName-$Ordinal" `
                #     -Priority                  1033
                $Ordinal += 1
            } else {
                $SourceName = ($Line -replace '\W+', '-').ToLower()
                $Ordinal    = 0
            }
        }
    }

    end {
        #$Group #| Set-AzureRmNetworkSecurityGroup
    }
}
