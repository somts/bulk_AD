###################################################################
#
#                Mass user load for AD for STS
#              Add users list to Active Directory 
#                      sts-cr@ucsd.edu
###################################################################
. .\Get-FileName.ps1

#Add AD bits and not complain if they're already there
Import-Module ActiveDirectory -ErrorAction SilentlyContinue


#Get domain DNS suffix
$dnsroot = '@' + (Get-ADDomain).dnsroot

#Path for AD
#Examples:
#OU=STS,OU=Users,OU=SOMTS,OU=SIO,DC=AD,DC=UCSD,DC=EDU
#CN=someuser,OU=People,DC=AD,DC=UCSD,DC=EDU

#Do/While proper input, User prompt if user wants to add or remove users.
Do
{
    $delonly = Read-Host -Prompt '[0]Do you want to Add Users[0], or [1]Remove old users[1]?
    Type number 0, or 1, then ENTER.'


    #################### Try, then catch all system exceptions ####################
    try
    {
        #################### If Users are being added ####################
        if($delonly -eq 0) 
        {
            #Prompt for mission ID
            $missionID = Read-Host -Prompt 'Input current mission ID (ex: SR1705).'
            $missionID = $missionID.ToUpper()
            #prompt for password, hide password. 
            $defpassword = Read-Host -AsSecureString 'Enter the default password (usually same as wifi)'
            #Prompt to choose .CSV file, then import user .CSV.
            try 
            {
                Write-Host "Choose the proper .csv file."
                $inputfile = Get-FileName 
                $users = Import-CSV $inputfile
            }
            catch [System.Object]
            {
                Write-Output "User cancelled, $_"
            }

            #Grab all users in OU=Disabled Users, and test during loop.
            $ExistingUsers = Get-ADUser -Filter * -SearchBase 'OU=Disabled Users,CN=Users,DC=rv-sallyride,DC=ucsd,DC=edu' 

            ##### Loop through $users memory, test if user exists, ####
            ##### else sort them in science or crew                ####
            foreach ($user in $users) 
            {
                try
                {
                    #Add users if description in csv file is science
                    if($user.Description -eq "science")
                    {                        
                        try 
                        {
                            #Loop to test each new user against disabled users, and add and enable them to current mission
                            foreach ($euser in $ExistingUsers)
                            {
                                if($euser.SamAccountName -eq $user.SamAccountName -and $euser.GivenName -eq $user.Firstname)
                                {
                                     Set-ADUser $euser -Description ($missionID+ " " + $user.Description.ToUpper())
                                     Get-ADUser $euser| Move-ADObject -TargetPath `
                                     'OU=Science,CN=Users,DC=rv-sallyride,DC=ucsd,DC=edu' 
                                     Write-Output "Moved existing user $($euser.SamAccountName) to Science"
                                     Enable-ADAccount -Identity $euser.SamAccountName
                                     Write-Output "Disabled user $($euser.SamAccountName) now re-enabled" 
                                     $test = @{$user = 1}  #Add $user property to object $test, so catch error is suppressed

                                }
                            }

                            New-ADUser -Name ($user.Firstname + " " + $user.LastName) -SamAccountName ($user.SamAccountName) `
                            -Description ($missionID + " " + $user.Description.ToUpper()) `
                            -DisplayName ($user.Firstname + " " + $user.LastName) -GivenName ($user.FirstName) -Surname ($user.LastName) `
                            -UserPrincipalName ($user.SamAccountName + $dnsroot) `
                            -AccountPassword $defpassword -PassThru `
                            -ChangePasswordAtLogon $true `
                            -Enabled $true `
                            -Path "OU=Science,CN=Users,DC=rv-sallyride,DC=ucsd,DC=edu"
                            Add-ADGroupMember -Identity www-science -Members $user.SamAccountName 
                         }
                         catch [System.Object]
                         {
                                if($test.$user -eq 1)  #If $test object's property $user exists, supress error
                                {}
                                else
                                { 
                                    Write-Output "Could not group user $($user.SamAccountName), $_ " 
                                }
                         }        
                    }
                    #Add users if description field in csv file is crew                       
                    Elseif($user.Description -eq "crew") 
                    {         
                        try 
                        {
                            New-ADUser -Name ($user.Firstname + " " + $user.LastName) -SamAccountName ($user.SamAccountName) `
                            -Description ($user.Description.ToUpper()) `
                            -DisplayName ($user.Firstname + " " + $user.LastName) -GivenName ($user.FirstName) -Surname ($user.LastName) `
                            -UserPrincipalName ($user.SamAccountName + $dnsroot) `
                            -AccountPassword $defpassword -PassThru `
                            -ChangePasswordAtLogon $true `
                            -Enabled $true `
                            -Path "OU=SR Crew,CN=Users,DC=rv-sallyride,DC=ucsd,DC=edu"
                            Add-ADGroupMember -Identity www-crew -Members $user.SamAccountName 
                         }
                         catch [System.Object]
                         {
                            Write-Output "Could not group user $($user.SamAccountName), $_ " 
                         }    
                     }
                    Else
                    {
                        Write-Output "Please specify 'Science' or 'Crew' in the description field in `
                        $($user.SamAccountName)'s line in the users.csv file."
                    } 
                 }
                 catch [System.Object]
                 {
                    Write-Output "Could not create user $($user.SamAccountName), $_ " `
                 }
        
            }
        }

        ################### If Users are being removed ###################
        elseif($delonly -eq 1)
        {
                #Prompt for mission ID
                $missionID = Read-Host -Prompt 'Input current mission ID (ex: SR1705). Any user not in current mission will be disabled'
                $missionID = $missionID.ToUpper()
                #Grab all users in OU=Science, and make sure to include Description in memory.
                $OldUsers = Get-ADUser -Filter * -SearchBase 'OU=Science,CN=Users,DC=rv-sallyride,DC=ucsd,DC=edu' `
                -Properties Description
                $nouser = 0
      
                Try
                {
                    foreach ($ouser in $OldUsers) 
                    {
                        #Pull just the Description property of each ouser in OldUser, compare if it !includes current missionID.
                        if($ouser.Description -notmatch "$missionID")
                        {
                            Set-ADUser $ouser -Description "SCIENCE"
                            Get-ADUser $ouser| Move-ADObject -TargetPath `
                            'OU=Disabled Users,CN=Users,DC=rv-sallyride,DC=ucsd,DC=edu' 
                            Write-Output "Moved $($ouser.Name) to Disabled Users"
                            Disable-ADAccount -Identity $ouser.SamAccountName
                            Write-Output "$($ouser.SamAccountName) Disabled"
                            $nouser++ 
                        } 
                    }
                    if($nouser -eq 0)
                    {
                        Write-Output "No old users found"
                    }
                }
                catch [System.Object]
                {
                    Write-Output "Exception. $_ Closing"
                }
          }
        ################# Improper user input,not 1 or 0 #################
        else
        {
            Write-Output "Invalid entry, Enter 1 or 0."
        } 
    }

    ######################### Catch all system exceptions #########################
    catch [System.Object]
    {
            Write-Output "Exception. $_ , Closing" 
    }
}while($delonly -ne 1 -and $delonly -ne 0)