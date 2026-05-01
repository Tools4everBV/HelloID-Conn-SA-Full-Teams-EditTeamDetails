#######################################################################
# Template: HelloID SA Powershell data source
# Name: teams-edit-team-details | Get-Team-Visibility-Options
# Date: 20-04-2026
#######################################################################

# For basic information about powershell data sources see:
# https://docs.helloid.com/en/service-automation/dynamic-forms/data-sources/powershell-data-sources.html

# Service automation variables:
# https://docs.helloid.com/en/service-automation/service-automation-variables.html

#region init

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# global variables (Automation --> Variable library):

# variables configured in form
$groupId = $datasource.selectedgroup.GroupId
$visibility = $datasource.selectedgroup.Visibility

#endregion init

#region functions

#endregion functions

try {
    $actionMessage = "getting Team visibility details for Team ID [$groupId]"
    Write-Information $actionMessage

    $returnObject = @(
        @{
            label    = 'Public'
            value    = 'Public'
            selected = if ($visibility -eq 'Public') { 1 } else { 0 }
        }
        @{
            label    = 'Private'
            value    = 'Private'
            selected = if ($visibility -eq 'Private') { 1 } else { 0 }
        }
    )

    if ($visibility -eq 'HiddenMembership') {
        $returnObject += @(
            @{
                label    = 'HiddenMembership'
                value    = 'HiddenMembership'
                selected = if ($visibility -eq 'HiddenMembership') { 1 } else { 0 }
            }
        )
    }
    Write-Output $returnObject
}
catch {
    $ex = $PSItem
    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    Write-Error "Error $($actionMessage). Error: $($ex.Exception.Message)"
    # exit # use when using multiple try/catch and the script must stop
}

