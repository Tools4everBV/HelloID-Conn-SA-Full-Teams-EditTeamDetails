#Input: TeamsAdminUser
#Input: TeamsAdminPWD

$connected = $false
try {
	Import-Module MicrosoftTeams
	$pwd = ConvertTo-SecureString -string $TeamsAdminPWD -AsPlainText –Force
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
	    $teams = Get-Team

        if(@($teams).Count -gt 0){
         foreach($team in $teams)
            {
                $addRow = @{DisplayName=$team.DisplayName; Description=$team.Description; MailNickName=$team.MailNickName; Visibility=$team.Visibility; Archived=$team.Archived; GroupId=$team.GroupId;}
                Hid-Write-Status -Message "$addRow" -Event Information
                Hid-Add-TaskResult -ResultValue $addRow
            }
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Teams. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Teams" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

