/*
 * An example of calling LsaLogonUser with KERB_SMART_CARD_LOGON under Windows 2000 and above
 *
 * Copyright (c) 2009 Mounir IDRASSI <mounir.idrassi@idrix.fr>. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */


/*#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0700
#endif					*/	

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Ntsecapi.h>
#include <iostream>
#include <intsafe.h>
#include <WinCred.h>
#include <winbase.h>

#pragma comment(lib, "Crypt32")

#define NEGOSSP_NAME_A  "Negotiate"


#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif
#include <vcruntime_exception.h>

#pragma comment(lib, "Secur32.lib")

using namespace std;

 // 1-Byte packing for this structure
#pragma pack(push, KerbCspInfo2, 1)
typedef struct _KERB_SMARTCARD_CSP_INFO_2
{
    DWORD dwCspInfoLen;
    DWORD dwUnknown;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer;
} KERB_SMARTCARD_CSP_INFO_2, * PKERB_SMARTCARD_CSP_INFO_2;
#pragma pack(pop, KerbCspInfo2)

// 1-Byte packing for this structure
#pragma pack(push, KerbCspInfo, 1)
typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;
    union {
        PVOID   ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer[sizeof(DWORD)];
} KERB_SMARTCARD_CSP_INFO, * PKERB_SMARTCARD_CSP_INFO;
#pragma pack(pop, KerbCspInfo)


static HRESULT _LsaInitString(
    __out PSTRING pszDestinationString,
    __in PCSTR pszSourceString
)
{
    size_t cchLength = strlen(pszSourceString);
    USHORT usLength;
    HRESULT hr = SizeTToUShort(cchLength, &usLength);
    if (SUCCEEDED(hr))
    {
        pszDestinationString->Buffer = (PCHAR)pszSourceString;
        pszDestinationString->Length = usLength;
        pszDestinationString->MaximumLength = pszDestinationString->Length + 1;
        hr = S_OK;
    }
    return hr;
}

HRESULT UnicodeStringInitWithString(
    _In_ PWSTR pwz,
    _Out_ UNICODE_STRING* pus
)
{
    HRESULT hr;
    if (pwz)
    {
        size_t lenString = wcslen(pwz);
        USHORT usCharCount;
        hr = SizeTToUShort(lenString, &usCharCount);
        if (SUCCEEDED(hr))
        {
            USHORT usSize;
            hr = SizeTToUShort(sizeof(wchar_t), &usSize);
            if (SUCCEEDED(hr))
            {
                hr = UShortMult(usCharCount, usSize, &(pus->Length)); // Explicitly NOT including NULL terminator
                if (SUCCEEDED(hr))
                {
                    pus->MaximumLength = pus->Length;
                    pus->Buffer = pwz;
                    hr = S_OK;
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
                }
            }
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

static void _UnicodeStringPackedUnicodeStringCopy(
    __in const UNICODE_STRING& rus,
    __in PWSTR pwzBuffer,
    __out UNICODE_STRING* pus
)
{
    pus->Length = rus.Length;
    pus->MaximumLength = rus.Length;
    pus->Buffer = pwzBuffer;

    std::CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

// Set the SeTcbPrivilege of the current process
BOOL SetSeTcbPrivilege()
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hProcessToken;
    int x;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        &hProcessToken))
    {
        _tprintf(_T("OpenProcessToken failed with error 0x%.8X\n"), GetLastError());
        cin >> x;
        return FALSE;
    }

    if (!LookupPrivilegeValue(
        NULL,
        SE_TCB_NAME,
        &luid))
    {
        _tprintf(_T("LookupPrivilegeValue failed with error 0x%.8X\n"), GetLastError());
        CloseHandle(hProcessToken);
        cin >> x;
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Enable the privilege
    if (!AdjustTokenPrivileges(
        hProcessToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        _tprintf(_T("AdjustTokenPrivileges failed with error 0x%.8X\n"), GetLastError());
        CloseHandle(hProcessToken);
        cin >> x;
        return FALSE;
    }


    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        _tprintf(_T("The token does not have the privilege \"SeTcbPrivilege\". \n"));
        CloseHandle(hProcessToken);
        cin >> x;
        return FALSE;
    }

    CloseHandle(hProcessToken);


    return TRUE;
}

// Build the authentication data used by LsaLogonUser

void ConstructAuthUPInfo(LPBYTE* ppbAuthInfo, ULONG* pulAuthInfoLen, const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn)
{
    HRESULT hr;


    

    const KERB_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

    // alloc space for struct plus extra for the three strings
    DWORD cb = sizeof(rkiulIn) +
        pkilIn->LogonDomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Password.Length;

    KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut = (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);
    if (pkiulOut)
    {
        std::ZeroMemory(&pkiulOut->LogonId, sizeof(pkiulOut->LogonId));

        //
        // point pbBuffer at the beginning of the extra space
        //
        BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        //
        // set up the Logon structure within the KERB_INTERACTIVE_UNLOCK_LOGON
        //
        KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;

        pkilOut->MessageType = pkilIn->MessageType;

        //
        // copy each string,
        // fix up appropriate buffer pointer to be offset,
        // advance buffer pointer over copied characters in extra space
        //
        _UnicodeStringPackedUnicodeStringCopy(pkilIn->LogonDomainName, (PWSTR)pbBuffer, &pkilOut->LogonDomainName);
        pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->LogonDomainName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
        pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->UserName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->Password, (PWSTR)pbBuffer, &pkilOut->Password);
        pkilOut->Password.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);

        *ppbAuthInfo = (BYTE*)pkiulOut;
        *pulAuthInfoLen = cb;

    }
}

void ConstructAuthCertInfo( KERB_CERTIFICATE_UNLOCK_LOGON& rkiulIn, /*const PKERB_SMARTCARD_CSP_INFO pCspInfo,*/
    LPBYTE* ppbAuthInfo, ULONG* pulAuthInfoLen)
{


    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Password;
    NTSTATUS Status;
    ULONG_PTR Ptr;

    PMSV1_0_INTERACTIVE_LOGON AuthInfo = NULL;
    ULONG AuthInfoLength;

    wchar_t domm[] = L"TECNICS";
    LPWSTR lpszDomain = domm;
    wchar_t pnn[] = L"12345678";
    LPWSTR lpszPassword = pnn;

    HCERTSTORE      hStoreHandle = NULL;
    PCCERT_CONTEXT  pCertContext = NULL;
    //CERT_ENHKEY_USAGE keyUsage;
    DWORD dwLogonCertsCount = 0;
    LPCTSTR pszStoreName = _T("MY");
    char szSCLogonOID[64];
    CERT_CREDENTIAL_INFO certInfo;
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BOOL bStatus;
    DWORD dwHashLen = CERT_HASH_LENGTH;
    LPWSTR szMarshaledCred = NULL;
    LPCTSTR szPIN = _T("");
    HANDLE hToken;



    hStoreHandle = CertOpenSystemStore(NULL, pszStoreName);
    wstring containerName;
    if (hStoreHandle)
    {

        // Find certificates that contain the Smart Card Logon Enhanced Key Usage
        pCertContext = CertFindCertificateInStore(
            hStoreHandle,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            NULL,
            NULL);

        if (pCertContext)
        {
            HCRYPTPROV hProv;
            DWORD dwKeySpec;
            BOOL bFreeHandle;

            // acquire private key to this certificate    
            if (CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, NULL, &hProv, &dwKeySpec, &bFreeHandle))
            {
                cout << "The private key container handle is accessed"<<endl;
            
                DWORD contSize = 0;
                if (CryptGetProvParam(hProv, PP_CONTAINER, NULL, &contSize, 0))
                {
                    BYTE* contName = (BYTE*)malloc(contSize);
                    if (CryptGetProvParam(hProv, PP_CONTAINER, contName, &contSize, 0))
                    {
                        containerName = wstring(contName, contName + contSize);
                        wcout << "The container name is: " << containerName << endl;
                    }
                    else
                    {
                        cout << "Could not get the container name. Falling back to Lolos..";
                        containerName = L"Lolos";

                    }
                }
                else
                {
                    cout << "Could not get the container size. Falling back to Lolos..";
                    containerName = L"Lolos";

                }

                // we take the first one in our example
                std::ZeroMemory(&certInfo, sizeof(certInfo));
                certInfo.cbSize = sizeof(certInfo);

                // compute the SHA-1 hash of the certificate
                bStatus = CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
                if (bStatus)
                {
                    bStatus = CryptCreateHash(hProv, CALG_SHA1, NULL, 0, &hHash);
                    if (bStatus)
                    {
                        bStatus = CryptHashData(hHash, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, 0);
                        if (bStatus)
                        {
                            bStatus = CryptGetHashParam(hHash, HP_HASHVAL, certInfo.rgbHashOfCert, &dwHashLen, 0);
                        }
                        CryptDestroyHash(hHash);
                    }
                    CryptReleaseContext(hProv, 0);
                }

                if (bStatus)
                {
                    bStatus = CredMarshalCredential(CertCredential, &certInfo, &szMarshaledCred);
                }
            }
        }
    }


    UnicodeStringInitWithString(lpszDomain, &DomainName);
    UnicodeStringInitWithString(szMarshaledCred, &UserName);
    UnicodeStringInitWithString(lpszPassword, &Password);


    //AuthInfoLength = sizeof(MSV1_0_INTERACTIVE_LOGON) +
    //    DomainName.MaximumLength +
    //    UserName.MaximumLength +
    //    Password.MaximumLength;

    /*AuthInfo = RtlAllocateHeap(RtlGetProcessHeap(),
        HEAP_ZERO_MEMORY,
        AuthInfoLength);
    if (AuthInfo == NULL)
    {
        cout << "cannot proceed!!";
        return;
    }*/

    //AuthInfo->MessageType = MsV1_0InteractiveLogon;

    //Ptr = (ULONG_PTR)AuthInfo + sizeof(MSV1_0_INTERACTIVE_LOGON);

    //AuthInfo->LogonDomainName.Length = DomainName.Length;
    //AuthInfo->LogonDomainName.MaximumLength = DomainName.MaximumLength;
    //AuthInfo->LogonDomainName.Buffer = (DomainName.Buffer == NULL) ? NULL : (PWCHAR)Ptr;
    //if (DomainName.MaximumLength > 0)
    //{
    //    RtlCopyMemory(AuthInfo->LogonDomainName.Buffer,
    //        DomainName.Buffer,
    //        DomainName.MaximumLength);

    //    Ptr += DomainName.MaximumLength;
    //}

    //AuthInfo->UserName.Length = UserName.Length;
    //AuthInfo->UserName.MaximumLength = UserName.MaximumLength;
    //AuthInfo->UserName.Buffer = (PWCHAR)Ptr;
    //if (UserName.MaximumLength > 0)
    //    RtlCopyMemory(AuthInfo->UserName.Buffer,
    //        UserName.Buffer,
    //        UserName.MaximumLength);

    //Ptr += UserName.MaximumLength;

    //AuthInfo->Password.Length = Password.Length;
    //AuthInfo->Password.MaximumLength = Password.MaximumLength;
    //AuthInfo->Password.Buffer = (PWCHAR)Ptr;
    //if (Password.MaximumLength > 0)
    //    RtlCopyMemory(AuthInfo->Password.Buffer,
    //        Password.Buffer,
    //        Password.MaximumLength);


    DWORD dwReaderLen = (DWORD)_tcslen(L"") + 1;
    DWORD dwCardLen = (DWORD)_tcslen(L"") + 1;
    DWORD dwProviderLen = (DWORD)_tcslen(L"Microsoft Enhanced Cryptographic Provider v1.0") + 1;
    DWORD dwContainerLen = (DWORD)_tcslen(containerName.c_str()) + 1;
    DWORD dwBufferSize = dwReaderLen + dwCardLen + dwProviderLen + dwContainerLen;

    PKERB_SMARTCARD_CSP_INFO CspInfo = (PKERB_SMARTCARD_CSP_INFO)malloc(sizeof(KERB_SMARTCARD_CSP_INFO) + dwBufferSize * sizeof(TCHAR));
    std::memset(CspInfo, 0, sizeof(KERB_SMARTCARD_CSP_INFO));
    CspInfo->dwCspInfoLen = sizeof(KERB_SMARTCARD_CSP_INFO) + dwBufferSize * sizeof(TCHAR);
    CspInfo->MessageType = 1;
    CspInfo->KeySpec = AT_KEYEXCHANGE;
    CspInfo->nCardNameOffset = ARRAYSIZE(CspInfo->bBuffer);
    CspInfo->nReaderNameOffset = CspInfo->nCardNameOffset + dwCardLen;
    CspInfo->nContainerNameOffset = CspInfo->nReaderNameOffset + dwReaderLen;
    CspInfo->nCSPNameOffset = CspInfo->nContainerNameOffset + dwContainerLen;
    std::memset(CspInfo->bBuffer, 0, sizeof(CspInfo->bBuffer));
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nCardNameOffset], dwBufferSize + 4 - CspInfo->nCardNameOffset, L"");
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nReaderNameOffset], dwBufferSize + 4 - CspInfo->nReaderNameOffset, L"");
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nContainerNameOffset], dwBufferSize + 4 - CspInfo->nContainerNameOffset, containerName.c_str());
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nCSPNameOffset], dwBufferSize + 4 - CspInfo->nCSPNameOffset, L"Microsoft Enhanced Cryptographic Provider v1.0");



    KERB_CERTIFICATE_LOGON* pkilIn = &rkiulIn.Logon;

    //pkilIn->UserName = UserName;


    //pkilIn->CspData = szMarshaledCred;
    // alloc space for struct plus extra for the three strings
    DWORD cb = sizeof(rkiulIn) +
        pkilIn->DomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Pin.Length +
        sizeof(szMarshaledCred);


    KERB_CERTIFICATE_UNLOCK_LOGON* pkiulOut = (KERB_CERTIFICATE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);

    if (pkiulOut)
    {
        std::ZeroMemory(&pkiulOut->LogonId, sizeof(LUID));

        //
        // point pbBuffer at the beginning of the extra space
        //
        BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        //
        // set up the Logon structure within the TEC_INTERACTIVE_UNLOCK_LOGON
        //
        KERB_CERTIFICATE_LOGON* pkilOut = &pkiulOut->Logon;
        //KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;

        pkilOut->MessageType = pkilIn->MessageType;
        pkilOut->Flags = pkilIn->Flags;

        //
        // copy each string,
        // fix up appropriate buffer pointer to be offset,
        // advance buffer pointer over copied characters in extra space
        //
        _UnicodeStringPackedUnicodeStringCopy(pkilIn->DomainName, (PWSTR)pbBuffer, &pkilOut->DomainName);
        pkilOut->DomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->DomainName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
        pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->UserName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->Pin, (PWSTR)pbBuffer, &pkilOut->Pin);
        pkilOut->Pin.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->Pin.Length;

        pkilOut->CspData = (PUCHAR)(pbBuffer - (BYTE*)pkiulOut);
        pkilOut->CspDataLength = sizeof(szMarshaledCred);

        std::memcpy(pbBuffer,szMarshaledCred, sizeof(szMarshaledCred));




        *ppbAuthInfo = (BYTE*)pkilOut;
        *pulAuthInfoLen = cb;
        
        return;
    }
}
    


void ConstructAuthInfo(LPCWSTR szReaderName,
    LPCWSTR szCardName,
    LPCWSTR szCspName,
    LPCWSTR szContainerName,
    LPCWSTR szPin,
    const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
    LPBYTE* ppbAuthInfo, ULONG* pulAuthInfoLen)
{

     ULONG ulPinByteLen = wcslen(szPin) * sizeof(WCHAR);
    LPBYTE pbAuthInfo = NULL;
    ULONG  ulAuthInfoLen = 0;
    KERB_SMART_CARD_LOGON* pKerbCertLogon;
    KERB_SMARTCARD_CSP_INFO_2* pKerbCspInfo;
    LPBYTE pbPinBuffer;
    LPBYTE pbCspData;
    LPBYTE pbCspDataContent;

    HCRYPTPROV nKey = NULL;
    HCRYPTPROV pKey = NULL;
    HCRYPTPROV HCryptProvv = NULL;
    HCRYPTPROV hKeyy = NULL;
    BOOL bStatus;
    int x;


    try
    {
        bStatus = CryptAcquireContext(&HCryptProvv,
            L"Lolos",
            MS_ENHANCED_PROV,
            PROV_RSA_FULL,
            CRYPT_SILENT);
        if (!bStatus)
        {
            printf("The container does not exist !!");
            cin >> x;
            return;

        }

    }
    catch (exception e)
    {
        printf("The error has been caught inside the catch block");
    }



    ULONG ulCspDataLen = sizeof(KERB_SMARTCARD_CSP_INFO_2) - sizeof(TCHAR) +
        (wcslen(szCardName) + 1) * sizeof(WCHAR) +
        (wcslen(szCspName) + 1) * sizeof(WCHAR) +
        (wcslen(szContainerName) + 1) * sizeof(WCHAR) +
        (wcslen(szReaderName) + 1) * sizeof(WCHAR);

    ulAuthInfoLen = sizeof(KERB_SMART_CARD_LOGON) +
        ulPinByteLen + sizeof(WCHAR) +
        ulCspDataLen;

    pbAuthInfo = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulAuthInfoLen);
    std::ZeroMemory(pbAuthInfo, ulAuthInfoLen);

    pbPinBuffer = pbAuthInfo + sizeof(KERB_SMART_CARD_LOGON);
    pbCspData = pbPinBuffer + ulPinByteLen + sizeof(WCHAR);

    std::memcpy(pbPinBuffer, szPin, ulPinByteLen);

    pKerbCertLogon = (KERB_SMART_CARD_LOGON*)pbAuthInfo;

    pKerbCertLogon->MessageType = KerbSmartCardLogon;
    pKerbCertLogon->Pin.Length = (USHORT)ulPinByteLen;
    pKerbCertLogon->Pin.MaximumLength = (USHORT)(ulPinByteLen + sizeof(WCHAR));
    pKerbCertLogon->Pin.Buffer = (PWSTR)pbPinBuffer;

    pKerbCertLogon->CspDataLength = ulCspDataLen;
    pKerbCertLogon->CspData = pbCspData;

    pKerbCspInfo = (KERB_SMARTCARD_CSP_INFO_2*)pbCspData;
    pKerbCspInfo->dwCspInfoLen = ulCspDataLen;

    pKerbCspInfo->nCardNameOffset = 0;
    pKerbCspInfo->nReaderNameOffset = pKerbCspInfo->nCardNameOffset + wcslen(szCardName) + 1;
    pKerbCspInfo->nContainerNameOffset = pKerbCspInfo->nReaderNameOffset + wcslen(szReaderName) + 1;
    pKerbCspInfo->nCSPNameOffset = pKerbCspInfo->nContainerNameOffset + wcslen(szContainerName) + 1;

    pbCspDataContent = pbCspData + sizeof(KERB_SMARTCARD_CSP_INFO_2) - sizeof(TCHAR);
    std::memcpy(pbCspDataContent + (pKerbCspInfo->nCardNameOffset * sizeof(WCHAR)), szCardName, wcslen(szCardName) * sizeof(WCHAR));
    std::memcpy(pbCspDataContent + (pKerbCspInfo->nReaderNameOffset * sizeof(WCHAR)), szReaderName, wcslen(szReaderName) * sizeof(WCHAR));
    std::memcpy(pbCspDataContent + (pKerbCspInfo->nContainerNameOffset * sizeof(WCHAR)), szContainerName, wcslen(szContainerName) * sizeof(WCHAR));
    std::memcpy(pbCspDataContent + (pKerbCspInfo->nCSPNameOffset * sizeof(WCHAR)), szCspName, wcslen(szCspName) * sizeof(WCHAR));

    *ppbAuthInfo = pbAuthInfo;
    *pulAuthInfoLen = ulAuthInfoLen;


}

int _tmain(int argc, _TCHAR* argv[])
{
    NTSTATUS nStatus;
    CHAR szProcName[] = "LsaTestLogonProcess";
    CHAR szPackageName[] = MICROSOFT_KERBEROS_NAME_A;
    CHAR szOriginName[] = "LsaSmartCardLogonTest";
    LSA_STRING lsaProcName = { strlen(szProcName), strlen(szProcName) + 1, szProcName };
    LSA_STRING lsaPackageName = { strlen(szPackageName), strlen(szPackageName) + 1, szPackageName };
    LSA_STRING lsaOriginName = { strlen(szOriginName), strlen(szOriginName) + 1, szOriginName };
    //LSA_STRING lsaszKerberosName;
    //_LsaInitString(&lsaszKerberosName, "Kerberos");
    HANDLE lsaHandle;
    ULONG ulAuthPackage;
    LPBYTE pbAuthInfo = NULL;
    ULONG  ulAuthInfoLen = 0;
    LSA_OPERATIONAL_MODE dummy;
    TOKEN_SOURCE tokenSource;
    LPVOID pProfileBuffer = NULL;
    ULONG ulProfileBufferLen = 0;
    LUID logonId;
    HANDLE hLogonToken;
    QUOTA_LIMITS quotas;
    NTSTATUS subStatus = STATUS_SUCCESS;
    HANDLE hToken = NULL;
    int x;
    wchar_t doman[] = L"TECNICS";
    wchar_t usernme[] = L"Test";
    wchar_t passwrd[] = L"12345678";
    wchar_t pn[] = L"12345678";
    PWSTR domain = doman;
    PWSTR username = usernme;
    PWSTR password = passwrd;
    PWSTR pin = pn;

    //Username-Password Based Auth
    
    KERB_INTERACTIVE_UNLOCK_LOGON pkiul;
    KERB_INTERACTIVE_LOGON* pkil = &pkiul.Logon;
    HRESULT hr;
    HCERTSTORE      hStoreHandle = NULL;
    PCCERT_CONTEXT  pCertContext = NULL;
    //CERT_ENHKEY_USAGE keyUsage;
    DWORD dwLogonCertsCount = 0;
    LPCTSTR pszStoreName = _T("MY");
    char szSCLogonOID[64];
    CERT_CREDENTIAL_INFO certInfo;
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BOOL bStatus;
    DWORD dwHashLen = CERT_HASH_LENGTH;
    LPWSTR szMarshaledCred = NULL;
    LPCTSTR szPIN = _T("");



    hStoreHandle = CertOpenSystemStore(NULL, pszStoreName);
    if (hStoreHandle)
    {
        // populate the key usage structure with the Smart Card Logon OID
        //strcpy(szSCLogonOID, szOID_KP_SMARTCARD_LOGON);
        //keyUsage.cUsageIdentifier = 1;
        //keyUsage.rgpszUsageIdentifier = (LPSTR*)LocalAlloc(0, sizeof(LPSTR));
        //keyUsage.rgpszUsageIdentifier[0] = &szSCLogonOID[0];

        // Find certificates that contain the Smart Card Logon Enhanced Key Usage
        pCertContext = CertFindCertificateInStore(
            hStoreHandle,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR,
            L"Demo",
            NULL);

        if (pCertContext)
        {
            // we take the first one in our example
            std::ZeroMemory(&certInfo, sizeof(certInfo));
            certInfo.cbSize = sizeof(certInfo);

            // compute the SHA-1 hash of the certificate
            bStatus = CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
            if (bStatus)
            {
                bStatus = CryptCreateHash(hProv, CALG_SHA1, NULL, 0, &hHash);
                if (bStatus)
                {
                    bStatus = CryptHashData(hHash, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, 0);
                    if (bStatus)
                    {
                        bStatus = CryptGetHashParam(hHash, HP_HASHVAL, certInfo.rgbHashOfCert, &dwHashLen, 0);
                    }
                    CryptDestroyHash(hHash);
                }
                CryptReleaseContext(hProv, 0);
            }

            if (bStatus)
            {
                bStatus = CredMarshalCredential(CertCredential, &certInfo, &szMarshaledCred);
            }
        }
    }
    UnicodeStringInitWithString(domain, &pkil->LogonDomainName);
    UnicodeStringInitWithString(szMarshaledCred, &pkil->UserName);
    UnicodeStringInitWithString(password, &pkil->Password);
    pkil->MessageType = KerbInteractiveLogon;
    //End


    //Certificate Based Auth
    KERB_CERTIFICATE_UNLOCK_LOGON ckiul;
    KERB_CERTIFICATE_LOGON* ckil = &ckiul.Logon;

    DWORD dwReaderLen = (DWORD)_tcslen(L"") + 1;
    DWORD dwCardLen = (DWORD)_tcslen(L"") + 1;
    DWORD dwProviderLen = (DWORD)_tcslen(L"Microsoft Enhanced Cryptographic Provider v1.0") + 1;
    DWORD dwContainerLen = (DWORD)_tcslen(L"Lolos") + 1;
    DWORD dwBufferSize = dwReaderLen + dwCardLen + dwProviderLen + dwContainerLen;

    PKERB_SMARTCARD_CSP_INFO CspInfo = (PKERB_SMARTCARD_CSP_INFO)malloc(sizeof(KERB_SMARTCARD_CSP_INFO) + dwBufferSize * sizeof(TCHAR));
    std::memset(CspInfo, 0, sizeof(KERB_SMARTCARD_CSP_INFO));
    CspInfo->dwCspInfoLen = sizeof(KERB_SMARTCARD_CSP_INFO) + dwBufferSize * sizeof(TCHAR);
    CspInfo->MessageType = 1;
    CspInfo->KeySpec = AT_KEYEXCHANGE;
    CspInfo->nCardNameOffset = ARRAYSIZE(CspInfo->bBuffer);
    CspInfo->nReaderNameOffset = CspInfo->nCardNameOffset + dwCardLen;
    CspInfo->nContainerNameOffset = CspInfo->nReaderNameOffset + dwReaderLen;
    CspInfo->nCSPNameOffset = CspInfo->nContainerNameOffset + dwContainerLen;
    std::memset(CspInfo->bBuffer, 0, sizeof(CspInfo->bBuffer));
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nCardNameOffset], dwBufferSize + 4 - CspInfo->nCardNameOffset, L"");
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nReaderNameOffset], dwBufferSize + 4 - CspInfo->nReaderNameOffset, L"");
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nContainerNameOffset], dwBufferSize + 4 - CspInfo->nContainerNameOffset,L"");
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nCSPNameOffset], dwBufferSize + 4 - CspInfo->nCSPNameOffset, L"");


    ckil->MessageType = KerbCertificateLogon;
    ckil->Flags = 2;
    UnicodeStringInitWithString(domain, &ckil->DomainName);
    UnicodeStringInitWithString(username, &ckil->UserName);
    UnicodeStringInitWithString(pin, &ckil->Pin);

    //End




    if (!SetSeTcbPrivilege())
    {
        cin >> x;
        //return -1;
    }

 
    std::memcpy(tokenSource.SourceName, "LsaTest", 8);
    AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);

    nStatus = LsaRegisterLogonProcess(&lsaProcName,
        &lsaHandle,
        &dummy);
    if (nStatus == STATUS_SUCCESS)
    {
        nStatus = LsaLookupAuthenticationPackage(lsaHandle,
            &lsaPackageName,
            &ulAuthPackage);
        if (nStatus == STATUS_SUCCESS)
        {

            ConstructAuthCertInfo(ckiul,/*CspInfo,*/ 
                &pbAuthInfo, &ulAuthInfoLen);

            nStatus = LsaLogonUser(lsaHandle,
                &lsaOriginName,
                Interactive,
                ulAuthPackage,
                pbAuthInfo,
                ulAuthInfoLen,
                NULL,
                &tokenSource,
                &pProfileBuffer,
                &ulProfileBufferLen,
                &logonId,
                &hLogonToken,
                &quotas,
                &subStatus);
            if (nStatus == STATUS_SUCCESS)
            {
                if (pProfileBuffer)
                    LsaFreeReturnBuffer(pProfileBuffer);

                _tprintf(_T("User logged on successfully!!\n"));
                cin >> x;
                CloseHandle(hLogonToken);
            }
            else
            {
                //if (LogonUserW(username, domain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
                //{
                //    _tprintf(_T("LogonUser works !! "));
                //}
                _tprintf(_T("LsaLogonUser failed with error 0x%.8X. SubStatus = 0x%.8X\n"), LsaNtStatusToWinError(nStatus), LsaNtStatusToWinError(subStatus));
                cin >> x;
            }


            HeapFree(GetProcessHeap(), 0, pbAuthInfo);
        }
        else
        {
            _tprintf(_T("LsaLookupAuthenticationPackage failed with error 0x%.8X\n"), LsaNtStatusToWinError(nStatus));
            cin >> x;
        }

        LsaDeregisterLogonProcess(lsaHandle);
    }
    else
    {
        _tprintf(_T("LsaRegisterLogonProcess failed with error 0x%.8X\n"), LsaNtStatusToWinError(nStatus));
        cin >> x;
    }

    return 0;
}

//int _tmain(int argc, _TCHAR* argv[])
//{
//    HCERTSTORE      hStoreHandle = NULL;
//    PCCERT_CONTEXT  pCertContext = NULL;
//    //CERT_ENHKEY_USAGE keyUsage;
//    DWORD dwLogonCertsCount = 0;
//    LPCTSTR pszStoreName = _T("MY");
//    char szSCLogonOID[64];
//    CERT_CREDENTIAL_INFO certInfo;
//    HCRYPTPROV hProv;
//    HCRYPTHASH hHash;
//    BOOL bStatus;
//    DWORD dwHashLen = CERT_HASH_LENGTH;
//    LPTSTR szMarshaledCred = NULL;
//    LPCTSTR szPIN = _T("");
//    HANDLE hToken;
//    int x;
//
//    // Open the "MY" certificate store
//    hStoreHandle = CertOpenSystemStore(NULL, pszStoreName);
//    if (hStoreHandle)
//    {
//        // populate the key usage structure with the Smart Card Logon OID
//        //strcpy(szSCLogonOID, szOID_KP_SMARTCARD_LOGON);
//        //keyUsage.cUsageIdentifier = 1;
//        //keyUsage.rgpszUsageIdentifier = (LPSTR*)LocalAlloc(0, sizeof(LPSTR));
//        //keyUsage.rgpszUsageIdentifier[0] = &szSCLogonOID[0];
//
//        // Find certificates that contain the Smart Card Logon Enhanced Key Usage
//        pCertContext = CertFindCertificateInStore(
//            hStoreHandle,
//            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
//            0,
//            CERT_FIND_SUBJECT_STR,
//            L"John@TECNICS.com",
//            NULL);
//
//        if (pCertContext)
//        {
//            // we take the first one in our example
//            ZeroMemory(&certInfo, sizeof(certInfo));
//            certInfo.cbSize = sizeof(certInfo);
//
//            // compute the SHA-1 hash of the certificate
//            bStatus = CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
//            if (bStatus)
//            {
//                bStatus = CryptCreateHash(hProv, CALG_SHA1, NULL, 0, &hHash);
//                if (bStatus)
//                {
//                    bStatus = CryptHashData(hHash, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, 0);
//                    if (bStatus)
//                    {
//                        bStatus = CryptGetHashParam(hHash, HP_HASHVAL, certInfo.rgbHashOfCert, &dwHashLen, 0);
//                    }
//                    CryptDestroyHash(hHash);
//                }
//                CryptReleaseContext(hProv, 0);
//            }
//
//            if (bStatus)
//            {
//                bStatus = CredMarshalCredential(CertCredential, &certInfo, &szMarshaledCred);
//                if (bStatus)
//                {
//                    bStatus = LogonUser(szMarshaledCred,
//                        NULL,
//                        szPIN,
//                        LOGON32_LOGON_INTERACTIVE,
//                        LOGON32_PROVIDER_DEFAULT,
//                        &hToken);
//
//                    if (bStatus)
//                    {
//                        _tprintf(_T("LogonUser success\n"));
//                        cin >> x;
//                        CloseHandle(hToken);
//                    }
//                    else
//                    {
//                        _tprintf(_T("LogonUser failed with error 0x%.8X\n"), GetLastError());
//                        cin >> x;
//                    }
//                    CredFree(szMarshaledCred);
//                }
//                else
//                {
//                    _tprintf(_T("CredMarshalCredential failed with error 0x%.8X\n"), GetLastError());
//                    cin >> x;
//                }
//            }
//            else
//            {
//                _tprintf(_T("Failed to compute logon certificate hash\n"));
//                cin >> x;
//            }
//
//            CertFreeCertificateContext(pCertContext);
//        }
//        else
//        {
//            _tprintf(_T("No Smart Card Logon certificate found\n"));
//            cin >> x;
//        }
//
//       /* LocalFree(keyUsage.rgpszUsageIdentifier);*/
//        CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
//    }
//    else
//    {
//        _tprintf(_T("CertOpenSystemStore failed with error 0x%.8X\n"), GetLastError);
//        cin >> x;
//    }
//
//    return 0;
//}

