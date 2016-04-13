<#

# requires -version 2.0 and x64 version

.SYNOPSIS
    Configures an IIS website

.DESCRIPTION
    This cmdlet enables you to re-create a website on IIS. 
    It also can handle the creation of multiple application pools and virtual directories (as required by your site to run).
    In addition to those, it configures the multiple binding scenario (http, https, net.tcp/net.pipe).

.PARAMETER:  IISConfigurationFile
    The path and file name of the .json file.  This file is used to configure the different settings for your IIS site.

.EXAMPLE
    .\CreateWebsite.ps1 -IISConfigurationFile C:\temp\MyWebsiteSettings.json

.NOTES
   Author: Meyliana Wangsa
   Created: 13/04/2016

   You need to run this script with an administrator access on the computer where you want to create the IIS site.

#>

[CmdletBinding()]
param(
    [string]
    $IISConfigurationFile
)


[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration")
Import-Module -Name WebAdministration -Global -ErrorAction Stop


<#
Function name: New-IIsApplicationPool
Description: this function creates the application pool based on the given parameters
#>
function New-IIsApplicationPool {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AppPoolName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('2.0', '4.0')]
        [string]$DotNetFramework,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Integrated', 'Classic')]
        [string]$PipelineMode,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('ApplicationPoolIdentity', 'LocalService', 'LocalSystem', 'NetworkService')]
        [string]$IdentityType,       

        [Parameter(Mandatory=$false)]
		[int]$RecycleInterval = 0,
        
        [Parameter(Mandatory=$true)]
        [bool]$Enable32BitAppOnWin64
    )
    
    $AppPool = Get-ChildItem IIS:\AppPools | Where-Object { $_.Name -eq $AppPoolName }
    
    if($AppPool -ne $null){
        Write-Host "Deleting old app pool: $AppPoolName"        
        Remove-WebAppPool -Name $AppPoolName
    }
    
    Write-Host "Creating app pool: $AppPoolName"    
    New-WebAppPool -Name $AppPoolName
    
    Set-ItemProperty IIS:\AppPools\$AppPoolName managedRuntimeVersion "v$DotNetFramework"
    Set-ItemProperty IIS:\AppPools\$AppPoolName -name managedPipelineMode -value ([int][Microsoft.Web.Administration.ManagedPipelineMode]::$PipelineMode)
    Set-ItemProperty IIS:\AppPools\$AppPoolName enable32BitAppOnWin64 $Enable32BitAppOnWin64
    Set-ItemProperty IIS:\AppPools\$AppPoolName -Name "processModel.idleTimeout" -Value "0"
	$Value = ("0"+ "$RecycleInterval" +":00:00")
	Set-ItemProperty IIS:\AppPools\$AppPoolName -Name "Recycling.periodicRestart.time" -Value $Value   
    Set-ItemProperty IIS:\AppPools\$AppPoolName -name processModel -value @{identitytype=$IdentityType}        
}

<#
Function name: New-IISVirtualAppDirectory
Description: this function creates either the virtual directory or web application (according to the VirtualType parameter value) 
             and configures it based on the parameter settings.
#>
function New-IISVirtualAppDirectory{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$VirtualWebName,

        [Parameter(Mandatory=$true)]
        [string]$VirtualPath,

        [Parameter(Mandatory=$false)]
        [string]$AppPoolName,

        [Parameter(Mandatory=$true)]
        [string]$WebsiteName,

        [Parameter(Mandatory=$true)]
        [string]$VirtualType,

        [Parameter(Mandatory=$false)]
        [bool]$WindowsAuthentication,

        [Parameter(Mandatory=$false)]
        [bool]$AnonymousAuthentication,

        [Parameter(Mandatory=$false)]
        [bool]$BasicAuthentication,

        [Parameter(Mandatory=$false)]
        [string]$clientcert,

        [Parameter(Mandatory=$false)]
        [int]$SSLFlags,

        [Parameter(Mandatory=$false)]
        [bool]$nettcp,

        [Parameter(Mandatory=$false)]
        [bool]$netpipe
    )

    $VirtualAppLocation = "$WebsiteName/$VirtualWebName"
    $VirtualAppPhysicalPath = "$WebsiteName/$VirtualPath"

     ("Creating {0}: {1}" -f $VirtualType, $VirtualWebName)
    New-Item IIS:\Sites\$WebsiteName\$VirtualWebName -physicalPath "$VirtualPath" -type $VirtualType


    if($VirtualType -ieq "Application"){
        Set-ItemProperty IIS:\sites\$VirtualAppLocation -name applicationPool -value $AppPoolName
    }

    # Set authentication mode
    if ($WindowsAuthentication -ne $null)
    {
		Set-WebConfigurationProperty -filter /system.WebServer/security/authentication/windowsAuthentication -name enabled -value $WindowsAuthentication -location "$VirtualAppLocation"
    }

    if ($AnonymousAuthentication -ne $null)
    {
		Set-WebConfigurationProperty -filter /system.WebServer/security/authentication/anonymousAuthentication -name enabled -value $AnonymousAuthentication -location "$VirtualAppLocation"
		Set-WebConfigurationproperty -filter /system.webServer/security/authentication/anonymousAuthentication -name userName -value "" -location "$VirtualAppLocation"
    }

    if ($BasicAuthentication -ne $null)
    {
		Set-WebConfigurationProperty -filter /system.WebServer/security/authentication/basicAuthentication -name enabled -value $BasicAuthentication -location "$VirtualAppLocation"
    }

    # Set the SSL mode 
    if ($clientcert -ne $null -and $clientcert -ne "")
	{
		if ($clientcert -ieq "Ignore"){
			$clientcert = "Ssl"	
		}
		elseif ($clientcert -ieq "Accept"){			
			$clientcert = "Ssl, SslNegotiateCert"
		}
		elseif ($clientcert -ieq "Require"){			
			$clientcert = "Ssl, SslNegotiateCert, SslRequireCert"
		}                
        
		Set-WebConfiguration -Location $VirtualAppLocation -Filter 'system.webserver/security/access' -Value $clientcert
	}

    if ($SSLFlags -ne $null -and $SSLFlags -ne '')
    {
        if ($SSLFlags -ieq 0){
            Set-WebConfigurationProperty -Filter "system.webserver/security/access" -Name SSLFlags -Value 0 -PSPath IIS:\ -Location $VirtualAppLocation
        }                
    }   

    # Configure the net.pipe/net.tcp protocols (if the site uses it)
    if($netpipe -ne $null -and $netpipe -ne "" -and $netpipe -ieq "true")
    {
        $enabledProtocols = Get-ItemProperty -Path IIS:\Sites\$VirtualAppPhysicalPath -name enabledProtocols
        $newEnabledProtocols = $enabledProtocols.Value + "," + "net.pipe"
        Set-ItemProperty -Path IIS:\Sites\$VirtualAppPhysicalPath -name enabledProtocols -value $newEnabledProtocols
    }

	if($nettcp -ne $null -and $nettcp -ne "" -and $nettcp -ieq "true")
    {
        $enabledProtocols = Get-ItemProperty -Path IIS:\Sites\$VirtualAppPhysicalPath -name enabledProtocols
        $newEnabledProtocols = $enabledProtocols.Value + "," + "net.tcp"
        Set-ItemProperty -Path IIS:\Sites\$VirtualAppPhysicalPath -name enabledProtocols -value $newEnabledProtocols
    }
}


try{

    if ( -not $IISConfigurationFile){
        Write-Error "Unable to read configuration file."
    }

    $IISConfiguration = Get-Content $IISConfigurationFile -Raw | ConvertFrom-Json

    $WebsiteName = $IISConfiguration.SiteName
    $PhysicalFilePath = $IISConfiguration.PhysicalPath
    $MainSitePoolName = $IISConfiguration.SitePoolName
    $ssl = $IISConfiguration.ssl
    $sslPort = $IISConfiguration.SslPort
    $IPAddress = $IISConfiguration.IPAddress
    $HostHeader = $IISConfiguration.HostHeader
    $SitePort = $IISConfiguration.SitePort
    $Certificate = $IISConfiguration.Certificate
    $WindowsAuthentication = $IISConfiguration.WindowsAuthentication
    $BasicAuthentication = $IISConfiguration.BasicAuthentication
    $AnonymousAuthentication = $IISConfiguration.AnonymousAuthentication
    $netpipe = $IISConfigurationFile.NetPipe
    $nettcp = $IISConfigurationFile.NetTcp

    # Create all application pools required
    foreach($AppPool in $IISConfiguration.AppPools){

        New-IIsApplicationPool -AppPoolName $AppPool.PoolName `
                                -IdentityType $AppPool.IdentityType `
                                -DotNetFramework $AppPool.DotnetFramework `
                                -PipelineMode $AppPool.pipelineMode `
                                -Enable32BitAppOnWin64 $AppPool.Enable32BitApponWin64 `
                                -RecycleInterval $AppPool.RecycleInterval
    }


    # Delete website if exists
    $SiteExisted = Get-ChildItem IIS:\Sites | Where-Object { $_.Name -eq $WebsiteName }
    if($SiteExisted -ne $null)
    {   
        Write-Host "Site existed - removing site: $WebsiteName"
        Remove-WebSite -Name $WebsiteName 
    }

    if (-not (Test-Path -Path $PhysicalFilePath -PathType Container)) {
        $null = New-Item -Path $PhysicalFilePath -ItemType Container
    }

    # Create the website
    $NewWebsiteParams = @{}
    if($IPAddress -ne "*")
    {
        $NewWebsiteParams['IPAddress'] = $IPAddress
    }
    
    if($HostHeader -ne "")
    {
        $NewWebsiteParams['HostHeader'] = $HostHeader
    }

    Write-Host "Creating site: $WebsiteName"
    New-Website -Name $WebsiteName -Port $SitePort -PhysicalPath $PhysicalFilePath -ApplicationPool $MainSitePoolName -Force @NewWebsiteParams

    # Configure SSL Binding
    if($ssl -ne $null -and $ssl -ieq "true")
    {
        New-WebBinding -Protocol https -Port $sslport -IPAddress $IPAddress -HostHeader $HostHeader -Name $WebsiteName

	    if($IPAddress -eq "*")
	    {
		    $IPAddress = "0.0.0.0"
	    }
	    $existingSslBinding = Get-Item "IIS:\SslBindings\$IPAddress!$sslport" -ErrorAction SilentlyContinue
	    if (-not $existingSslBinding)
	    {
	        Get-ChildItem cert:\LocalMachine\My | where { $_.Subject -like "*$Certificate*" } | select -First 1 | New-Item "IIS:\SslBindings\$IPAddress!$sslport"
	    }
    }    

    # Configure net.pipe/net.tcp binding    
    if($netpipe -ne $null -and $netpipe -ne "" -and $netpipe -ieq "true")
    {
        New-ItemProperty "IIS:\sites\$WebsiteName" -name bindings -value @{protocol="net.pipe";bindingInformation="*"}      
        $enabledProtocols = Get-ItemProperty -Path IIS:\Sites\$WebsiteName -name enabledProtocols
        $enabledProtocols =  $enabledProtocols + "," + "net.pipe"
        Set-ItemProperty -Path IIS:\Sites\$WebsiteName -name enabledProtocols -value $enabledProtocols
    }

    if($nettcp -ne $null -and $nettcp -ne "" -and $nettcp -ieq "true")
    {
        New-ItemProperty "IIS:\sites\$WebsiteName" -name bindings -value @{protocol="net.tcp";bindingInformation="808:*"}		
        $enabledProtocols = Get-ItemProperty -Path IIS:\Sites\$WebsiteName -name enabledProtocols
        $enabledProtocols =  $enabledProtocols + "," + "net.tcp"
        Set-ItemProperty -Path IIS:\Sites\$WebsiteName -name enabledProtocols -value $enabledProtocols
    }

    # Configure authentication mode
    Set-WebConfigurationProperty -filter /system.WebServer/security/authentication/windowsAuthentication -name enabled -value $WindowsAuthentication -location $WebsiteName
    Set-WebConfigurationProperty -filter /system.WebServer/security/authentication/anonymousAuthentication -name enabled -value $AnonymousAuthentication -location $WebsiteName
    Set-WebConfigurationproperty -filter /system.webServer/security/authentication/anonymousAuthentication -name userName -value "" -location $WebsiteName
    Set-WebConfigurationProperty -filter /system.WebServer/security/authentication/basicAuthentication -name enabled -value $BasicAuthentication -location $WebsiteName


    # Create all the virtual directory required
    foreach ($VirtualDirectory in $IISConfiguration.VirtualDirectories)
    {   

        New-IISVirtualAppDirectory -VirtualWebName $VirtualDirectory.VirtualName `
                                    -VirtualPath $VirtualDirectory.VirtualPath `
                                    -AppPoolName $VirtualDirectory.PoolName `
                                    -clientcert $VirtualDirectory.ClientCert  `
                                    -WebsiteName $WebsiteName `
                                    -VirtualType $VirtualDirectory.Type `
                                    -WindowsAuthentication $WindowsAuthentication `
                                    -AnonymousAuthentication $AnonymousAuthentication `
                                    -BasicAuthentication $BasicAuthentication 
    }
}
catch [System.Exception]
{
    Write-Error "*** ERROR: error encountered: $_.Exception.Message ***" 
}