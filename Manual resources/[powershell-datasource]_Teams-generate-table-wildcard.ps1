# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try {
    $searchValue = $datasource.searchValue
    $searchQuery = "*$searchValue*"
      
      
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        return
    }else{
        Write-Information -Message "Generating Microsoft Graph API Access Token user.."

        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$AADTenantID/oauth2/token"

        $body = @{
            grant_type      = "client_credentials"
            client_id       = "$AADAppId"
            client_secret   = "$AADAppSecret"
            resource        = "https://graph.microsoft.com"
        }
 
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token;

        Write-Information -Message "Searching for: $searchQuery"
        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept = "application/json";
        }
 
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + "v1.0/groups" + "?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')"                        
        $teamsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false          

        $teams = foreach($teamObject in $teamsResponse.value){
            if($teamObject.displayName -like $searchQuery -or $teamObject.mailNickName -like $searchQuery){
                $teamObject
            }
        }

        $teams = $teams | Sort-Object -Property DisplayName
        $resultCount = @($teams).Count
        Write-Information -Message "Result count: $resultCount"
         
        if($resultCount -gt 0){
            foreach($team in $teams){
                $channelUri = $baseSearchUri + "v1.0/teams" + "/$($team.id)/channels"                
                $channel = Invoke-RestMethod -Uri $channelUri -Method Get -Headers $authorization -Verbose:$false
                $returnObject = @{DisplayName=$team.DisplayName; Description=$team.Description; MailNickName=$team.MailNickName; Mailaddress=$team.Mail; Visibility=$team.Visibility; GroupId=$team.Id}
                Write-Output $returnObject
            }
        } else {
            return
        }
    }
} catch {
    
    Write-Error -Message ("Error searching for Teams-enabled AzureAD groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
    Write-Warning -Message "Error searching for Teams-enabled AzureAD groups"
     
    return
}
