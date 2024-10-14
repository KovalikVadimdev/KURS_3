#define _WIN32_DCOM
#include <iostream>
#include <thread> // Для std::this_thread::sleep_for
#include <chrono> // Для std::chrono::seconds
#include <comdef.h>
#include <Wbemidl.h>
#include <iomanip> // Для std::setw

#pragma comment(lib, "wbemuuid.lib")

int main(int argc, char** argv)
{
    HRESULT hres;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        std::cout << "Failed to initialize COM library. Error code = 0x"
            << std::hex << hres << std::endl;
        return 1;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );

    if (FAILED(hres))
    {
        std::cout << "Failed to initialize security. Error code = 0x"
            << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;                    // Program has failed.
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        std::cout << "Failed to create IWbemLocator object."
            << " Err code = 0x"
            << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices* pSvc = NULL;

    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
        NULL,                    // User name. NULL = current user
        NULL,                    // User password. NULL = current
        0,                       // Locale. NULL indicates current
        NULL,                    // Security flags.
        0,                       // Authority (for example, Kerberos)
        0,                       // Context object 
        &pSvc                    // pointer to IWbemServices proxy
    );

    if (FAILED(hres))
    {
        std::cout << "Could not connect. Error code = 0x"
            << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return 1;                // Program has failed.
    }

    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        std::cout << "Could not set proxy blanket. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }


	std::wcout << std::left << std::setw(50) << L"Process Name" << std::setw(30) <<  L"PID" << std::setw(30) << L"CPU Usage" << std::endl;

    while (true)
    {
        // Step 6: --------------------------------------------------
        // Use the IWbemServices pointer to make requests of WMI ----

        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_PerfFormattedData_PerfProc_Process"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator);

        if (FAILED(hres))
        {
            std::cout << "Query for operating system name failed."
                << " Error code = 0x"
                << std::hex << hres << std::endl;
            break; // Exit loop on error
        }

        // Step 7: -------------------------------------------------
        // Get the data from the query in step 6 -------------------

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        double first = 0;
		double second = 0;
		int i = 0;
        while (pEnumerator)
        {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (0 == uReturn)
            {
                break;
            }

            VARIANT vtName, vtProcessId, vtPercentProcessorTime;

			VariantInit(&vtName);
            VariantInit(&vtProcessId);
			VariantInit(&vtPercentProcessorTime);

			// Get the value of the Name property
			hr = pclsObj->Get(L"Name", 0, &vtName, 0, 0);
			if (SUCCEEDED(hr))
			{
				// Get the value of the ProcessId property
				hr = pclsObj->Get(L"IDProcess", 0, &vtProcessId, 0, 0);
				if (SUCCEEDED(hr))
				{
					
					hr = pclsObj->Get(L"PercentProcessorTime", 0, &vtPercentProcessorTime, 0, 0);
                    if (SUCCEEDED(hr)) {

                        std::wcout << std::left << std::setw(50) << vtName.bstrVal << std::setw(30) << vtProcessId.uintVal << std::setw(30) << std::wcstod(vtPercentProcessorTime.bstrVal, NULL) / 100 / 4 * 100 << std::endl;
                    }
                    else {

						std::wcout << "PercentProcessorTime not found" << std::endl;
                    }

				}
				else
				{
                    std::wcout << "ProcessId not found" << std::endl;
				}
			}
			else
			{
                std::wcout << "Name not found" << std::endl;
			}

            VariantClear(&vtName);
            VariantClear(&vtProcessId);
			VariantClear(&vtPercentProcessorTime);


            pclsObj->Release();
        }

        // Cleanup
        pEnumerator->Release();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Cleanup
    // ========
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return 0;   // Program successfully completed.
}
