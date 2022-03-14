#Input: TeamsAdminUser
#Input: TeamsAdminPWD

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Boolean values come in as string, use this function to convert these to booleans
function Convert-StringToBoolean {
    param(
        [parameter(Mandatory = $true)]$String
    )
    try {
        if(-not[String]::IsNullOrEmpty($String)){
            $boolean = [System.Convert]::ToBoolean($String)
            return $boolean
        }else{
            Write-Verbose "Provided value equals null or empty. Cannot convert to Boolean"
        }
    } catch {
        throw $_
    }
}

function Remove-EmptyValuesFromHashtable {
    param(
        [parameter(Mandatory = $true)][Hashtable]$Hashtable
    )

    $newHashtable = @{}
    foreach ($Key in $Hashtable.Keys) {
        if (-not[String]::IsNullOrEmpty($Hashtable.$Key)) {
            $null = $newHashtable.Add($Key, $Hashtable.$Key)
        }
    }
    
    return $newHashtable
}

# variables configured in form
$groupId                            =   $form.teams.GroupId
$AllowAddRemoveApps                 =   Convert-StringToBoolean $form.AllowAddRemoveApps
$AllowChannelMentions               =   Convert-StringToBoolean $form.AllowChannelMentions
$AllowCreateUpdateChannels          =   Convert-StringToBoolean $form.AllowCreateUpdateChannels
$AllowCreateUpdateRemoveConnectors  =   Convert-StringToBoolean $form.AllowCreateUpdateRemoveConnectors
$AllowCreateUpdateRemoveTabs        =   Convert-StringToBoolean $form.AllowCreateUpdateRemoveTabs 
$AllowCustomMemes                   =   Convert-StringToBoolean $form.AllowCustomMemes
$AllowDeleteChannels                =   Convert-StringToBoolean $form.AllowDeleteChannels
$AllowGiphy                         =   Convert-StringToBoolean $form.AllowGiphy
$AllowGuestCreateUpdateChannels     =   Convert-StringToBoolean $form.AllowGuestCreateUpdateChannels
$AllowGuestDeleteChannels           =   Convert-StringToBoolean $form.AllowGuestDeleteChannels
$AllowOwnerDeleteMessages           =   Convert-StringToBoolean $form.AllowOwnerDeleteMessages
$AllowStickersAndMemes              =   Convert-StringToBoolean $form.AllowStickersAndMemes
$AllowTeamMentions                  =   Convert-StringToBoolean $form.AllowTeamMentions
$AllowUserDeleteMessages            =   Convert-StringToBoolean $form.AllowUserDeleteMessages
$AllowUserEditMessages              =   Convert-StringToBoolean $form.AllowUserEditMessages
$ShowInTeamsSearchAndSuggestions    =   Convert-StringToBoolean $form.ShowInTeamsSearchAndSuggestions

$connected = $false
try {
	$module = Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	$teamsConnection = Connect-MicrosoftTeams -Credential $cred
    Write-Information "Connected to Microsoft Teams"
    $connected = $true
}
catch
{	
    Write-Error "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)"
}

if ($connected)
{
	try {
        $splatParams = @{
            groupId                             =   $groupId
            AllowAddRemoveApps                  =   $AllowAddRemoveApps
            AllowChannelMentions                =   $AllowChannelMentions
            AllowCreateUpdateChannels           =   $AllowCreateUpdateChannels 
            AllowCreateUpdateRemoveConnectors   =   $AllowCreateUpdateRemoveConnectors 
            AllowCreateUpdateRemoveTabs         =   $AllowCreateUpdateRemoveTabs 
            AllowCustomMemes                    =   $AllowCustomMemes 
            AllowDeleteChannels                 =   $AllowDeleteChannels 
            AllowGiphy                          =   $AllowGiphy
            AllowGuestCreateUpdateChannels      =   $AllowGuestCreateUpdateChannels
            AllowGuestDeleteChannels            =   $AllowGuestDeleteChannels
            AllowOwnerDeleteMessages            =   $AllowOwnerDeleteMessages
            AllowStickersAndMemes               =   $AllowStickersAndMemes 
            AllowTeamMentions                   =   $AllowTeamMentions 
            AllowUserDeleteMessages             =   $AllowUserDeleteMessages 
            AllowUserEditMessages               =   $AllowUserEditMessages 
            ShowInTeamsSearchAndSuggestions     =   $ShowInTeamsSearchAndSuggestions
        }

        # Remove empty or null values
        $splatParams = Remove-EmptyValuesFromHashtable $splatParams

		$updateTeam = Set-Team @splatParams
		Write-Information "Successfully updated Team [$groupId]"
	}
	catch
	{
		Write-Error "Could not update Team [$groupId]. Error: $($_.Exception.Message)"
	}
}
