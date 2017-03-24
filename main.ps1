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

#Import user CSV with user info.
#$users = Import-CSV C:\users\sts-cr\desktop\users.csv 

#Prompt user if they want to add users, or remove old users only.  Remove old users to be added in the future.
$delonly = Read-Host -Prompt '[0]Do you want to Add Users (removes old users as well)[0], or [1]Remove old users only[1]? 
Type number 0, or 1, then ENTER.  Do not press 1 yet.  Option not yet available.'


try
{
    if($delonly -eq 0) 
    {
        $missionID = Read-Host -Prompt 'Input mission ID (ex: SR1705)'
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

    foreach ($user in $users) 
                                                                                                                                                                                                    {
        try 
        {
             #There are 2 types of users: Science and Crew, Case sensitive
             if($user.Description -eq "Science")
                {                        
                    try 
                    {
                        New-ADUser -Name ($user.Firstname + " " + $user.LastName) -SamAccountName ($user.SamAccountName) -Description ($missionID + " " + $user.Description.ToUpper()) `
                        -DisplayName ($user.Firstname + " " + $user.LastName) -GivenName ($user.FirstName) -Surname ($user.LastName) `
                        -UserPrincipalName ($user.SamAccountName + $dnsroot) `
                        -AccountPassword $defpassword -PassThru `
                        -ChangePasswordAtLogon $true `
                        -Enabled $true `
                        -Path "OU=Science,CN=Users,DC=rv-sallyride,DC=ucsd,DC=edu"
                        Add-ADGroupMember -Identity www-science -Members $user.SamAccountName `
                     }
                     catch [System.Object]
                     {
                        Write-Output "Could not group user $($user.SamAccountName), $_ " `
                     }        
                 }
                                    
             Elseif($user.Description -eq "Crew") 
                 {         
                    try 
                    {
                        New-ADUser -Name ($user.Firstname + " " + $user.LastName) -SamAccountName ($user.SamAccountName) -Description ($user.Description.ToUpper()) `
                        -DisplayName ($user.Firstname + " " + $user.LastName) -GivenName ($user.FirstName) -Surname ($user.LastName) `
                        -UserPrincipalName ($user.SamAccountName + $dnsroot) `
                        -AccountPassword $defpassword -PassThru `
                        -ChangePasswordAtLogon $true `
                        -Enabled $true `
                        -Path "OU=SR Crew,CN=Users,DC=rv-sallyride,DC=ucsd,DC=edu"
                        Add-ADGroupMember -Identity www-crew -Members $user.SamAccountName `
                     }
                     catch [System.Object]
                     {
                        Write-Output "Could not group user $($user.SamAccountName), $_ " `
                     }    
                  }
               Else
                  {
                    Write-Output "Please specify 'Science' or 'Crew' (case-sensitive) in description in $($user.SamAccountName)'s line in the users.csv file."
                  }
                
             }
           

        catch [System.Object]
                {
                Write-Output "Could not create user $($user.SamAccountName), $_ " `
                }
    }

    #Move old mission users to Disabled Users.  To be added in future. 
 <#
    $OldUsers = Get-ADGroupMember -Identity www-science| Import-Csv -path .\temp.csv 

    ForEach ($ouser in $OldUsers) 
     {
      $Usercheck = Get-ADUser -Properties Description
         if($Usercheck -notcontains $missionID) 
         {
             Write-Host "Moving $user to Disabled Users"
             Get-ADUser $ouser| Move-ADObject -TargetPath 'OU=Disabled Users,CN=Users,DC=rv-sallyride,DC=ucsd,DC=edu' 
             Set-ADUser $ouser -Description "SCIENCE"
         }
      }
  #>
 
    }
    elseif($delonly -eq 1)
    {

        Write-Output "Not available yet.  Closing"
        #Move old mission users to Disabled Users.
        <#
        $OldUsers = Get-ADGroupMember -Identity www-science| Import-Csv -path .\temp.csv 

        ForEach ($ouser in $OldUsers) 
         {
          $Usercheck = Get-ADUser -Properties Description
             if($Usercheck -notcontains $missionID) 
             {
                 Write-Host "Moving $user to Disabled Users"
                 Get-ADUser $ouser| Move-ADObject -TargetPath 'OU=Disabled Users,CN=Users,DC=rv-sallyride,DC=ucsd,DC=edu' 
                 Set-ADUser $ouser -Description "SCIENCE"
             }
          }
          #>
    }
    else
    {
        Write-Output "Invalid entry, Closing"
    }

}

#Catch all handling.
catch [System.Object]
{
        Write-Output "Exception. $_ , Closing" `
}
