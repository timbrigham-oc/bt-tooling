<#
    This script is intended to be used with the BeyondTrust API to set the password for accounts that are not managed by the system for specific accounts.
    This is useful if you are onboarding in batches, and want to be able to apply changes to all mapped accounts across multiple domains, for multiple accounts. 
    There isn't a good many to many mapping native to the BeyondTrust API I have been able to find. 
    
    The flow is as follows. 
    * Read a CSV file with a single column named 'name' and look for accounts that match the name in the CSV file.
    * Get  the all managed accounts in BeyondTrust using a 'Map Dedicated Accounts To' Smart Rule. 
    * Verify that the managed accounts match the naming convention dictated, for example "username-ADMIN"
    * Check the LastChangeDate and AutoManagementFlag properties of the managed account.
    * If the account is not managed and has not had a password change, force a password change.

    The runasuser group membership needs to have the bare minimum permissions in order to read everything, and change the password for managed accounts. 
    The following have been validated, but might be too permissive for some environments.

    Smart Groups
    All Assets | Full Control | Information Security Administrator
    All Managed Accounts | Full Control | Credentials Manager 
    All Managed Systems | Full Control | NA 

    Features
    Password Safe Account Management | Full Control | NA
#>

# This is the root path for the BeyondTrust API, this is the same for all API calls.
# This assumes version3 of the API is being used. It also needs to reflect the instance name. 
$rootPath = "https://xxxxxxxxxxxxxxxxxxxxxxxxxxx/BeyondTrust/api/public/v3"
$runAsUser = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
# This assumes that the BeyondTrust API key for $runAsUser is present under the system enviroment variable BTPSAPI
$headers = @{
    'Authorization' = "PS-Auth key=$($env:BTPSAPI); runas=$runAsUser;"
    'Content-Type'  = "application/json"
}
# This is the session variable that will be used to store session state for the API calls.
$session = $null 
# These are the domains that will be checked for managed accounts.
$domains = @(
    "xxxxxxxxxxxxxxxx.com",
    "yyyyyyyyyyyyyyyy.net"
)
Function StartSession {
    # Start a session with the API credentials, this will store the session in a global variable for later use.
    try {
        Write-Host "Starting session with API user details:"
        Invoke-RestMethod -Uri "$script:rootPath/Auth/SignAppin" -Headers $headers -Method POST -SessionVariable session
        # Store the session in a global variable for later use, this is a global variable so it can be used in other functions
        $script:session = $session 
    }
    catch {
        Throw "Unable to sign in with API token, check it is a valid value for the $runAsUser user."
    }
}
Function EndSession {
    # Exit the session with the API, this will clear the session in the global variable.
    Invoke-RestMethod -Uri "$script:rootPath/Auth/Signout" -WebSession $script:session -Method POST
    $script:session = $null 
}
Function GetAllManagedAccounts {
    # Get all managed accounts for the domains in the $domains variable.
    $returnMe = @()
    foreach ( $domain in $script:domains ) {
        $getDomainURI = "$($script:rootPath)/ManagedSystems?name=$domain"
        try { $domainObject = Invoke-RestMethod -Uri $getDomainURI -WebSession $script:session -Method GET } catch { $domainObject = $null }
        $domainManagedSystemID = $domainObject.ManagedSystemID
        $getManagedAccountsURI = "$($script:rootPath)/ManagedSystems/$domainManagedSystemID/ManagedAccounts"
        try { $domainManagedAccounts = Invoke-RestMethod -Uri $getManagedAccountsURI -WebSession $script:session -Method GET } catch { $domainManagedAccounts = $null }
        # Output the total number of managed accounts discovered; this should match the number of accounts 
        # that are managed in the BeyondTrust system *for the domains listed in the $domains variable*.
        # This is important as it will not include accounts that are not domain accounts, and managed by BeyondTrust.
        # The count here can be validated by viewing "Managed Accounts" in the BeyondTrust console, and selecting the domain. 
        # The count show should match the number of accounts discovered here.
        $count = $domainManagedAccounts | Measure-Object | Select-Object -Expand Count 
        Write-Host "Total Accounts Discovered for $($domain): $count "
        # Add the managed accounts to the returnMe array. This is lazy coding with a += to an array, but it works for this purpose.
        $returnMe += $domainManagedAccounts
    }
    return $returnMe
}

Function SetManagedAccountPassword {
    # Set the password for a managed account, this is a POST request to the API. 
    # It needs to have the managedAccountID as a parameter.
    param (
        [parameter(mandatory = $true)]$managedAccountID
    )
    # This calls the "Change" endpoint for the managed account, this will set the password for the account.
    $setPasswordURI = "$($script:rootPath)/ManagedAccounts/$managedAccountID/Credentials/Change"
    Write-Host "Changing Credentials on endpoint: $setPasswordURI "
    # As a sanity check, you should review the actions this script will take before uncommenting this line. 
    # If applied inaccurately, this could be destructive. 
    #try { $results = Invoke-RestMethod -Uri $setPasswordURI -WebSession $script:session -Method POST } catch { $results = $null }
    return $results
}

# First establish a session for use with the API
StartSession 
# Get a list of all managed accounts 
$managedAccounts = GetAllManagedAccounts
# Now we get the list of account names from the CSV file. 
$csv = Import-Csv -Path ".\set_password.csv"
Write-Output "`n`n`n---------------------------------------------`n`n`n"
Write-Output "Now looking for accounts that need to be updated."

foreach ( $name in $csv.name ) {
    # Find the account in the managed accounts list that have a "username-ADMINISTRATOR" entry.  
    # Note - if your organization uses another naming convention such as "ADM-username" you should update the line below. 
    $accounts = $managedAccounts | Where-Object { $_.AccountName -like "$name-ADMINISTRATOR" }
    Write-Output "Looking for $name-* accounts based on CSV file"
    foreach ( $account in $accounts ) {
        # Use an API call to set the password for the account. Only needed when the account LastChangeDate is null and the AutoManagementFlag is false. 
        if ( ( $null -eq $account.LastChangeDate ) -and ( $account.AutoManagementFlag -eq $false ) ) {
            Write-Output "Setting password for #$($account.ManagedAccountID) $($account.AccountName)"
            SetManagedAccountPassword -managedAccountID $account.ManagedAccountID
        }
        else {
            Write-Output "Skipping account #$($account.ManagedAccountID) $($account.AccountName) as it is configured"
        }
    }
}

EndSession 

