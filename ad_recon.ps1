function Main {
    $domain = $args[0]
    #$domain = Get-WmiObject win32_computersystem | %{$_.domain}
    $provider = 'LDAP://' + $domain
    $provider = New-Object System.DirectoryServices.DirectoryEntry($domain)

    $queries = 'users', 'groups', 'computers'
    $queries | % {
        $q = $_
        '=' * 79
        'PRINTING: ' + $q
        $results = BuildSearcher $domain $q
        PrintResults $results
    }

    "`n--- End of Results ---"
    
    return
}

function BuildSearcher {
    $provider = $args[0]
    $search_type = $args[1]
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($provider)
    switch ($search_type) {
        'users'     { $object_cat = 'user' }
        'groups'    { $object_cat = 'group' }
        'computers' { $object_cat = 'computer'}
        default     { $object_cat = $search_type }
    }
    $searcher.Filter = "((objectcategory=$object_cat))"
    
    return $searcher.FindAll()
}

function PrintResults {
    $results = $args[0]
    $results | % { $_.properties} | % {
        $result_obj = $_
        switch -regex ($result_obj.objectcategory) {
            '^CN=Person.*'   { PrintUsers $result_obj }
            '^CN=Group.*'    { PrintGroups $result_obj }
            '^CN=Computer.*' { PrintComputers $result_obj }
            default          { $result_obj }
        }  
    }
    
    return
}

function PrintUsers {
    $r = $args[0]
    $last_logon = ConvertDateTime $r.lastlogontimestamp
    $acct_expires = ConvertDateTime $r.accountexpires

    '---'
    'Account Name      : ' + $r.samaccountname
    'Admin Account     : ' + $r.admincount
    'Description       : ' + $r.description
    'Created On        : ' + $r.whencreated
    'Changed On        : ' + $r.whenchanged
    'Last Logon        : ' + $last_logon
    'Account Expires   : ' + $acct_expires
    'Number Of Logons  : ' + $r.logoncount
    GetUacFlags $r.useraccountcontrol | % {
        'Account Flags     : ' + $_
    }
    $r.memberof | % {
        'Member Of         : ' + $_
    }
    
    return
}

function PrintGroups {
    $r = $args[0]
    
    '---'
    'Group Name        : ' + $r.samaccountname
    'Admin Group       : ' + $r.admincount
    'Description       : ' + $r.description
    'Created On        : ' + $r.whencreated
    'Changed On        : ' + $r.whenchanged
    $r.memberof | % {
        'Member Of         : ' + $_
    }
    
    return
}

function PrintComputers {
    $r = $args[0]
    $last_logon = ConvertDateTime $r.lastlogontimestamp
    $last_logoff = ConvertDateTime $r.lastlogoff
    $acct_expires = ConvertDateTime $r.accountexpires
    $pwd_last_set = ConvertDateTime $r.pwdlastset

    '---'
    'Computer Name     : ' + $r.name
    'FQDN              : ' + $r.dnshostname
    'Description       : ' + $r.description
    'Created On        : ' + $r.whencreated
    'Changed On        : ' + $r.whenchanged
    'Last Logon        : ' + $last_logon
    'Last Logoff       : ' + $last_logoff
    'Logon Count       : ' + $r.logoncount
    'Account Expires   : ' + $acct_expires
    'Password Last Set : ' + $pwd_last_set
    'Bad Passwords     : ' + $r.badpwdcount
    'Operating System  : ' + $r.operatingsystem
    'OS Version        : ' + $r.operatingsystemversion
    'OS Service Pack   : ' + $r.operatingsystemservicepack   
    GetUacFlags $r.useraccountcontrol | % {
        'Account Flags     : ' + $_
    }
    
    return
}

function ConvertDateTime {
    $dt = $args[0]
    #[DateTime]::FromFileTime($dt)
    # Convert from IADsLargerInteger to human readable date/time
    [DateTime]::FromFileTime([Int64]::Parse($dt))
    trap [Exception] {
        # Invalid timestamp
        return $null
    }
    
    return
}

function GetUacFlags {
    # Credit to Brandon Shell and TedWagne for this bit of code
    $uac = [string] $args[0]
    $uac_flags = @()
    
    switch ($uac) {
        {($uac -bor 1) -eq $uac}        {$uac_flags += "SCRIPT"}
        {($uac -bor 2) -eq $uac}        {$uac_flags += "ACCOUNTDISABLE"}
        {($uac -bor 8) -eq $uac}        {$uac_flags += "HOMEDIR_REQUIRED"}
        {($uac -bor 16) -eq $uac}       {$uac_flags += "LOCKOUT"}
        {($uac -bor 32) -eq $uac}       {$uac_flags += "PASSWD_NOTREQD"}
        {($uac -bor 64) -eq $uac}       {$uac_flags += "PASSWD_CANT_CHANGE"}
        {($uac -bor 128) -eq $uac}      {$uac_flags += "ENCRYPTED_TEXT_PWD_ALLOWED"}
        {($uac -bor 256) -eq $uac}      {$uac_flags += "TEMP_DUPLICATE_ACCOUNT"}
        {($uac -bor 512) -eq $uac}      {$uac_flags += "NORMAL_ACCOUNT"}
        {($uac -bor 2048) -eq $uac}     {$uac_flags += "INTERDOMAIN_TRUST_ACCOUNT"}
        {($uac -bor 4096) -eq $uac}     {$uac_flags += "WORKSTATION_TRUST_ACCOUNT"}
        {($uac -bor 8192) -eq $uac}     {$uac_flags += "SERVER_TRUST_ACCOUNT"}
        {($uac -bor 65536) -eq $uac}    {$uac_flags += "DONT_EXPIRE_PASSWORD"}
        {($uac -bor 131072) -eq $uac}   {$uac_flags += "MNS_LOGON_ACCOUNT"}
        {($uac -bor 262144) -eq $uac}   {$uac_flags += "SMARTCARD_REQUIRED"}
        {($uac -bor 524288) -eq $uac}   {$uac_flags += "TRUSTED_FOR_DELEGATION"}
        {($uac -bor 1048576) -eq $uac}  {$uac_flags += "NOT_DELEGATED"}
        {($uac -bor 2097152) -eq $uac}  {$uac_flags += "USE_DES_KEY_ONLY"}
        {($uac -bor 4194304) -eq $uac}  {$uac_flags += "DONT_REQ_PREAUTH"}
        {($uac -bor 8388608) -eq $uac}  {$uac_flags += "PASSWORD_EXPIRED"}
        {($uac -bor 16777216) -eq $uac} {$uac_flags += "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION"}
    }

    return $uac_flags
}

Main $args[0]
