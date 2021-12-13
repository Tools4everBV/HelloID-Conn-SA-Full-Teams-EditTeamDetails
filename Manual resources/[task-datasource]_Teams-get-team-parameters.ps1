#Input: TeamsAdminUser
#Input: TeamsAdminPWD
$groupId = $formInput.selectedGroup.GroupId
#$groupId = '0293ec24-013d-4a3a-ba2b-7836ef8f15dd'

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
	    $teams = Get-Team -GroupId $groupId

        if(@($teams).Count -eq 1){
         $returnObject = [ordered]@{}
         foreach($tmp in $teams.psObject.properties)
            {
                $returnObject.add($tmp.Name,$tmp.value)
            }
         Hid-Add-TaskResult -ResultValue $returnObject
        }else{
            Hid-Add-TaskResult -ResultValue []
        }
	}
	catch
	{
		HID-Write-Status -Message "Error getting Team Parameters. Error: $($_.Exception.Message)" -Event Error
		HID-Write-Summary -Message "Error getting Team Parameters" -Event Failed
		Hid-Add-TaskResult -ResultValue []
	}
}
else
{
	Hid-Add-TaskResult -ResultValue []
}

