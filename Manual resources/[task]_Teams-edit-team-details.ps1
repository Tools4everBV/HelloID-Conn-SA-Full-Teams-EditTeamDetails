$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText -Force
	$cred = New-Object System.Management.Automation.PSCredential $TeamsAdminUser, $pwd
	Connect-MicrosoftTeams -Credential $cred
    HID-Write-Status -Message "Connected to Microsoft Teams" -Event Information
    HID-Write-Summary -Message "Connected to Microsoft Teams" -Event Information
	$connected = $true
}
catch
{	
    HID-Write-Status -Message "Could not connect to Microsoft Teams. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to connect to Microsoft Teams" -Event Failed
}
if ($connected)
{
	try {
		Set-Team -groupId $groupId -AllowAddRemoveApps $AllowAddRemoveApps -AllowChannelMentions $AllowChannelMentions -AllowCreateUpdateChannels $AllowCreateUpdateChannels -AllowCreateUpdateRemoveConnectors $AllowCreateUpdateRemoveConnectors -AllowCreateUpdateRemoveTabs $AllowCreateUpdateRemoveTabs -AllowCustomMemes $AllowCustomMemes -AllowDeleteChannels $AllowDeleteChannels -AllowGiphy $AllowGiphy -AllowGuestCreateUpdateChannels $AllowGuestCreateUpdateChannels -AllowGuestDeleteChannels $AllowGuestDeleteChannels -AllowOwnerDeleteMessages $AllowOwnerDeleteMessages -AllowStickersAndMemes $AllowStickersAndMemes -AllowTeamMentions $AllowTeamMentions -AllowUserDeleteMessages $AllowUserDeleteMessages -AllowUserEditMessages $AllowUserEditMessages -ShowInTeamsSearchAndSuggestions $ShowInTeamsSearchAndSuggestions
		HID-Write-Status -Message "Updated Team [$groupId]" -Event Success
		HID-Write-Summary -Message "Successfully update Team [$groupId]" -Event Success
	}
	catch
	{
		HID-Write-Status -Message "Could not update Team [$groupId]. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Failed to update Team [$groupId]" -Event Failed
	}
}
