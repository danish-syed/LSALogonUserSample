
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



BOOL ConstructAuthCertInfo(const KERB_CERTIFICATE_UNLOCK_LOGON& rkiulIn,LPBYTE* ppbAuthInfo, ULONG* pulAuthInfoLen)
{
    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Password;
    NTSTATUS Status;
    ULONG_PTR Ptr;
    ULONG AuthInfoLength;
    wstring WProvName;
    DWORD ProvSize = 0;
    wstring containerName;
    DWORD contSize = 0;
    HCRYPTPROV hProv;
    DWORD dwKeySpec;

    // Fetching the certificate context from the certificate store  
    // and recieving the CSP handle for the user certificate
    HCERTSTORE      hStoreHandle = NULL;
    PCCERT_CONTEXT  pCertContext = NULL;
    LPCTSTR pszStoreName = _T("MY");
    CERT_CREDENTIAL_INFO certInfo;
    HCRYPTHASH hHash;
    BOOL bStatus;
    DWORD dwHashLen = CERT_HASH_LENGTH;
    LPWSTR szMarshaledCred = NULL;
    HANDLE hToken;

    hStoreHandle = CertOpenSystemStore(NULL, pszStoreName);

    if (hStoreHandle)
    {
        // Since my certificate store has only one user certificate, tring to retrieve PCERT_CONTEXT for it
        pCertContext = CertFindCertificateInStore(
            hStoreHandle,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            NULL,
            NULL);

        if (pCertContext)
        {

            BOOL bFreeHandle;

            // acquire private key container to this certificate    
            if (CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, NULL, &hProv, &dwKeySpec, &bFreeHandle))
            {
                cout << "The private key container handle is accessed.. "<<endl<<"The dwKeySpec Value is: "<<dwKeySpec<<endl;
            

                //Fetching the container name where the certificate is stored
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
                        cout << "Could not get the container name. Exiting.."<<endl;
                        return FALSE;

                    }
                }
                else
                {
                    cout << "Could not get the container size. Exiting.."<<endl;
                    return FALSE;

                }

                //Fetching the CSP name where the certificate is stored
                if (CryptGetProvParam(hProv, PP_NAME, NULL, &ProvSize, 0))
                {
                    BYTE* ProvName = (BYTE*)malloc(ProvSize);
                    if (CryptGetProvParam(hProv, PP_NAME, ProvName, &ProvSize, 0))
                    {
                        WProvName = wstring(ProvName, ProvName + ProvSize);
                        wcout << "The name of the CSP is: " << WProvName << endl;
                    }
                    else
                    {
                        cout << "The CSP name could not be retrieved. Exiting.." << endl;
                        return FALSE;
                    }
                }
                else
                {
                    cout << "The CSP name size could not be retrieved. Exiting.." << endl;
                    return FALSE;
                }

             }
            else
            {
                cout << "Could not get the Private Key Container handle. Exiting...";
                return FALSE;
            }
        }
        else
        {
            cout << "Could not find the user certificate in the Certificate store. Exiting.." << endl;
            return FALSE;
        }
    }


    
    // Creating and initializing a PKERB_SMARTCARD_CSP_INFO struct for passing as an argument to KERB_CERTIFICATE_LOGON struct
    // This struct stores information regarding the CSP and container of the user certs

    DWORD dwReaderLen = (DWORD)_tcslen(L"") + 1;
    DWORD dwCardLen = (DWORD)_tcslen(L"") + 1;
    DWORD dwProviderLen = (DWORD)_tcslen(WProvName.c_str()) + 1;
    DWORD dwContainerLen = (DWORD)_tcslen(containerName.c_str()) + 1;
    DWORD dwBufferSize = dwReaderLen + dwCardLen + dwProviderLen + dwContainerLen;

    PKERB_SMARTCARD_CSP_INFO CspInfo = (PKERB_SMARTCARD_CSP_INFO)malloc(sizeof(KERB_SMARTCARD_CSP_INFO) + dwBufferSize * sizeof(TCHAR));
    std::memset(CspInfo, 0, sizeof(KERB_SMARTCARD_CSP_INFO));
    CspInfo->dwCspInfoLen = sizeof(KERB_SMARTCARD_CSP_INFO) + dwBufferSize * sizeof(TCHAR);
    CspInfo->MessageType = 1;
    CspInfo->KeySpec = dwKeySpec;
    CspInfo->nCardNameOffset = ARRAYSIZE(CspInfo->bBuffer);
    CspInfo->nReaderNameOffset = CspInfo->nCardNameOffset + dwCardLen;
    CspInfo->nContainerNameOffset = CspInfo->nReaderNameOffset + dwReaderLen;
    CspInfo->nCSPNameOffset = CspInfo->nContainerNameOffset + dwContainerLen;
    std::memset(CspInfo->bBuffer, 0, sizeof(CspInfo->bBuffer));
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nCardNameOffset], dwBufferSize + 4 - CspInfo->nCardNameOffset, L"");
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nReaderNameOffset], dwBufferSize + 4 - CspInfo->nReaderNameOffset, L"");
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nContainerNameOffset], dwBufferSize + 4 - CspInfo->nContainerNameOffset, containerName.c_str());
    _tcscpy_s(&CspInfo->bBuffer[CspInfo->nCSPNameOffset], dwBufferSize + 4 - CspInfo->nCSPNameOffset, WProvName.c_str());




    
    const KERB_CERTIFICATE_LOGON* pkilIn = &rkiulIn.Logon;

    // alloc space for struct plus extra for the three strings
    DWORD cb = sizeof(rkiulIn) +
        pkilIn->DomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Pin.Length +
        CspInfo->dwCspInfoLen;

    KERB_CERTIFICATE_UNLOCK_LOGON* pkiulOut = (KERB_CERTIFICATE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);

    if (pkiulOut)
    {
        std::ZeroMemory(&pkiulOut->LogonId, sizeof(LUID));

        //
        // point pbBuffer at the beginning of the extra space
        //
        BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        //
        // set up the Logon structure within the KERB_CERTIFICATE_UNLOCK_LOGON
        //
        KERB_CERTIFICATE_LOGON* pkilOut = &pkiulOut->Logon;

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
        pkilOut->CspDataLength = CspInfo->dwCspInfoLen;

        std::memcpy(pbBuffer,CspInfo, CspInfo->dwCspInfoLen);




        *ppbAuthInfo = (BYTE*)pkilOut;
        *pulAuthInfoLen = cb;
        
        return TRUE;
    }
}
  


int _tmain(int argc, _TCHAR* argv[])
{
    NTSTATUS nStatus;
    CHAR szProcName[] = "LsaTestLogonProcess";
    CHAR szPackageName[] = NEGOSSP_NAME_A;
    CHAR szOriginName[] = "LsaSmartCardLogonTest";
    LSA_STRING lsaProcName = { strlen(szProcName), strlen(szProcName) + 1, szProcName };
    LSA_STRING lsaPackageName = { strlen(szPackageName), strlen(szPackageName) + 1, szPackageName };
    LSA_STRING lsaOriginName = { strlen(szOriginName), strlen(szOriginName) + 1, szOriginName };
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
    NTSTATUS subStatus;
    HANDLE hToken = NULL;



    int x;
    wchar_t doman[] = L"TECNICS";
    wchar_t usernme[] = L"";
    wchar_t pn[] = L"";
    PWSTR domain = doman;
    PWSTR username = usernme;
    PWSTR pin = pn;


    //Certificate Based Auth
    KERB_CERTIFICATE_UNLOCK_LOGON ckiul;
    KERB_CERTIFICATE_LOGON* ckil = &ckiul.Logon;

    ckil->MessageType = KerbCertificateLogon;
    ckil->Flags = 2;

    // Converting Domain Name to Unicode Format
    UnicodeStringInitWithString(domain, &ckil->DomainName);

    // Passing empty UserName as per https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon
    UnicodeStringInitWithString(username, &ckil->UserName);

    // Passing empty PIN since no PIN asked during enrollment
    UnicodeStringInitWithString(pin, &ckil->Pin);
    //End




    if (!SetSeTcbPrivilege())
    {
        cin >> x;
        return 0;
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

            if (!ConstructAuthCertInfo(ckiul, &pbAuthInfo, &ulAuthInfoLen))
            {
                cout << "Could not serialize the authentication data. Exiting...";
                cin >> x;
                return 0;
            }

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
