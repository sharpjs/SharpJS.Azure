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
        Creates a set of inbound rules allowing a list of source addresses, and merges into existing rules for a network security group.
    #>
    [CmdletBinding()]
    param (
        # Name of the resource group to which the network security group belongs.
        [Parameter(Mandatory, Position=0)]
        [string] $ResourceGroupName,

        # Name of the network security group.
        [Parameter(Mandatory, Position=1)]
        [string] $NetworkSecurityGroupName,

        # Source names and addresses to be matched by the generated rules.  Interpreted line-by-line as follows:
        #
        # - Blank lines are ignored.
        #
        # - Lines in IP or CIDR format generate rules allowing inbound traffic from the specified addresses.
        #
        # - Any other line sets the name used for subsequent lines.  Uppercase characters are transformed to lowercase.  Non-word sequences are transformed to '-'.
        [Parameter(Mandatory, Position=2, ValueFromPipeline)]
        [AllowEmptyString()]
        [string[]] $Sources,

        # Network protocols to be matched by the generated rules.  Accepted values are:
        #
        # - * (default value; matches any protocl)
        # - Tcp
        # - Udp
        [ValidateSet("*", "Tcp", "Udp")]
        [string] $Protocol = "*",

        # Names and ranges of destination ports to be matched by the generated rules.  Examples:
        #
        # - @{ any = "*" }              # default value; matches any port
        # - @{ http = 80 }              # matches port 80, uses name 'http'
        # - @{ ftp = 20-21 }            # matches ports 20 and 21, uses name 'ftp'
        # - @{ http = 80; https = 443 } # multiple possible matches
        [Parameter()]
        [hashtable] $DestinationPorts = @{ all = "*" },

        # Starting priority for generated rules.
        [Parameter()]
        [int] $Priority = 2000
    )

    begin {
        Write-Verbose "Getting network security group '$NetworkSecurityGroupName' in resource group '$ResourceGroupName'."
        $Group = Get-AzureRmNetworkSecurityGroup `
            -Name              $NetworkSecurityGroupName `
            -ResourceGroupName $ResourceGroupName

        Write-Verbose "Getting network security group inbound rules."
        $Rules = $Group | Get-AzureRmNetworkSecurityRuleConfig | ? Direction -EQ Inbound

        # Sort destination specs
        Write-Verbose "Preparing..."
        $Destinations = [ordered] @{}
        $DestinationPorts.GetEnumerator() `
            | sort Value, Key `
            | % { $Destinations.Add($_.Key, $_.Value) }

        # Default name until source list provides one
        $SourceName = "ip"
        $Ordinal    = 0
    }

    process {
        foreach($Line in $Sources -split '\r?\n') {
            $Line = $Line.Trim()

            if (-not $Line) {
                # Empty line; ignore
            } elseif ($Line -match $AddressRe) {
                # Is it an IP address?
                $Address = $Line

                # Remove existing rules for this address, if any
                $Rules | ? {
                    $Address             -eq $_.SourceAddressPrefix  -and
                    $Destinations.Values -eq $_.DestinationPortRange
                } | % {
                    Write-Verbose "Removing rule: $($_.Name)"
                    $Group | Remove-AzureRmNetworkSecurityRuleConfig $_.Name
                }

                # Add new rule for each destination port range
                $Destinations.GetEnumerator() | % {
                    $ServiceName = $_.Key
                    $PortRange   = $_.Value
                    $RuleName    = "allow-$ServiceName-from-$SourceName-$Ordinal"

                    Write-Verbose "Creating rule: $RuleName"

                    $Group `
                        | Add-AzureRmNetworkSecurityRuleConfig `
                            -Direction                 Inbound `
                            -Protocol                  $Protocol `
                            -SourceAddressPrefix       $Address `
                            -SourcePortRange           * `
                            -DestinationAddressPrefix  * `
                            -DestinationPortRange      $PortRange `
                            -Access                    Allow `
                            -Name                      $RuleName `
                            -Priority                  $Priority `
                        | Out-Null

                    $Ordinal  += 1
                    $Priority += 1
                }
            } else {
                $SourceName = ($Line -replace '\W+', '-').ToLower()
                $Ordinal    = 0
            }
        }
    }

    end {
        $Group #| Set-AzureRmNetworkSecurityGroup
    }
}
