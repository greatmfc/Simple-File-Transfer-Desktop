#include <iostream>
#include <format>
#include <vector>
#include <Winsock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>
#include <ShObjIdl.h>
#include <comdef.h>
#include <netfw.h>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "oleaut32.lib")

#define RuleNameIn L"sft-win Inbound"
#define RuleNameOut L"sft-win Outbound"

struct NameIP {
	std::string name;
	std::string ip;
};

std::string get_winsock_error_str(int errcode = 0) {
	CHAR message[128]{};
	DWORD ecode = GetLastError();
	FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM,
		nullptr,
		errcode ? errcode : ecode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		message,
		sizeof(message) - 1,
		nullptr
	);
	return std::format("{} {}", message, ecode);
}

std::wstring OpenFileDialog() {
	std::wstring result;

	// 初始化 COM 库
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	if (FAILED(hr)) {
		return L"COM Failed";
	}

	// 创建文件对话框实例
	IFileDialog* pFileDialog = NULL;
	hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileDialog, (void**)&pFileDialog);
	if (SUCCEEDED(hr)) {
		// 设置对话框选项（可选）
		DWORD dwFlags;
		pFileDialog->GetOptions(&dwFlags);
		pFileDialog->SetOptions(dwFlags | FOS_FORCEFILESYSTEM); // 强制选择文件系统对象

		// 显示对话框（控制台程序无窗口，传 NULL）
		hr = pFileDialog->Show(NULL);

		if (SUCCEEDED(hr)) {
			// 获取用户选择结果
			IShellItem* pItem;
			hr = pFileDialog->GetResult(&pItem);
			if (SUCCEEDED(hr)) {
				// 提取文件路径
				PWSTR pszFilePath;
				hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
				if (SUCCEEDED(hr)) {
					result = pszFilePath;
					CoTaskMemFree(pszFilePath);
				}
				pItem->Release();
			}
		} else if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
			// 用户取消选择
			result = L"";
		}

		pFileDialog->Release();
	}

	CoUninitialize();
	return result;
}

bool CheckFirewallRuleExists(const wchar_t* targetRuleName) {
	HRESULT hr = S_OK;
	INetFwPolicy2* pFwPolicy = NULL;
	INetFwRules* pFwRules = NULL;
	bool exists = false;

	hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2), (void**)&pFwPolicy);
	if (FAILED(hr)) {
		SetLastError(hr);
		perror("Fail to create instance");
		return false;
	}

	hr = pFwPolicy->get_Rules(&pFwRules);
	if (FAILED(hr)) {
		SetLastError(hr);
		perror("Fail to get rules");
		pFwPolicy->Release();
		return false;
	}

	INetFwRule* pRule = NULL;
	hr = pFwRules->Item(_bstr_t(targetRuleName), &pRule);
	if (SUCCEEDED(hr)) {
		exists = true;
	}
	// 释放资源
	pFwRules->Release();
	pFwPolicy->Release();
	return exists;
}

// 定义GUID（某些旧版SDK可能缺少这些定义）
HRESULT AddFirewallRule(INetFwPolicy2* pFwPolicy, const wchar_t* ruleName,
	const wchar_t* appPath, NET_FW_RULE_DIRECTION direction, NET_FW_IP_PROTOCOL protocol) {

	HRESULT hr = S_OK;
	INetFwRule* pFwRule = NULL;

	// 创建规则实例
	hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER,
		__uuidof(INetFwRule), (void**)&pFwRule);
	if (FAILED(hr)) {
		SetLastError(hr);
		perror("Fail to create rule instance");
		return hr;
	}

	// 配置规则属性
	pFwRule->put_Name(_bstr_t(ruleName));
	pFwRule->put_ApplicationName(_bstr_t(appPath));
	pFwRule->put_Action(NET_FW_ACTION_ALLOW);
	pFwRule->put_Direction(direction);
	pFwRule->put_Enabled(VARIANT_TRUE);
	pFwRule->put_Protocol(protocol);

	// 添加规则到策略
	INetFwRules* pFwRules = NULL;
	hr = pFwPolicy->get_Rules(&pFwRules);
	if (SUCCEEDED(hr)) {
		//pFwRules->Remove(_bstr_t(ruleName));
		hr = pFwRules->Add(pFwRule);
	}
	if (FAILED(hr)) {
		SetLastError(hr);
		perror("Fail to add rules");
	}

	pFwRule->Release();
	return hr;
}

bool ConfigureFirewall() {
	HRESULT hr = S_OK;
	INetFwPolicy2* pFwPolicy = NULL;
	// 检查管理员权限
	BOOL isAdmin = FALSE;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	WCHAR exePath[MAX_PATH];
	bool add_in = true, add_out = true;

	// 初始化COM
	hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	if (FAILED(hr)) {
		SetLastError(hr);
		perror("COM initialization failed");
		return false;
	}
	add_in = !CheckFirewallRuleExists(RuleNameIn);
	add_out = !CheckFirewallRuleExists(RuleNameOut);
	if (!add_in && !add_out) {
		CoUninitialize();
		return true;
	}

	GetModuleFileNameW(NULL, exePath, ARRAYSIZE(exePath));
	if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
		CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
		FreeSid(AdministratorsGroup);
	}

	if (!isAdmin) {
		SHELLEXECUTEINFO sei = { sizeof(sei) };

		sei.fMask = SEE_MASK_NO_CONSOLE;
		sei.lpVerb = L"runas";
		sei.lpFile = exePath;
		sei.hwnd = NULL;
		sei.nShow = SW_SHOWDEFAULT;

		if (!ShellExecuteExW(&sei)) {
			std::cerr << "Please run the program in admin privilege. " << get_winsock_error_str();
			std::cerr << "The following results are not guaranteed." << std::endl;
			CoUninitialize();
			return false;
		}
		if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
			CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
			FreeSid(AdministratorsGroup);
		}
		if (!isAdmin) {
			CoUninitialize();
			Sleep(500);
			return true;
		}
	}

	// 获取防火墙策略实例
	hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2), (void**)&pFwPolicy);
	if (FAILED(hr)) {
		SetLastError(hr);
		perror("Fail to create policy instance");
		return false;
	}

	// 添加规则
	bool success = true;

	// 入站
	if (add_in) {
		hr = AddFirewallRule(pFwPolicy, RuleNameIn, exePath, NET_FW_RULE_DIR_IN, NET_FW_IP_PROTOCOL_ANY);
		success &= SUCCEEDED(hr);
	}
	// 出站
	if (add_out) {
		hr = AddFirewallRule(pFwPolicy, RuleNameOut, exePath, NET_FW_RULE_DIR_OUT, NET_FW_IP_PROTOCOL_ANY);
		success &= SUCCEEDED(hr);
	}

	pFwPolicy->Release();
	CoUninitialize();
	exit(0);
	//return success;
}

std::wstring convert_string_to_wstring(const char* str) {
	std::wstring wres;
	int convertResult = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
	if (convertResult <= 0) {
		wres = L"";
	} else {
		wres.resize(convertResult);
		convertResult = MultiByteToWideChar(CP_UTF8, 0, str, -1, wres.data(), convertResult);
		if (convertResult <= 0) {
			wres = L"";
		}
	}
	return wres;
}

std::string convert_wstring_to_string(const wchar_t* wstr) {
	std::string res;
	if (wstr == nullptr) {
		return res;
	}

	// 获取所需缓冲区大小（包含终止符）
	int bufferSize = WideCharToMultiByte(
		CP_UTF8,                // ANSI代码页
		0,                     // 转换选项
		wstr,                 // 源字符串
		-1,                   // 自动计算源字符串长度（-1表示NUL终止）
		nullptr,              // 目标缓冲区
		0,                    // 目标缓冲区大小
		nullptr,              // 默认字符（使用系统默认）
		nullptr               // 是否使用了默认字符
	);

	if (bufferSize == 0) {
		return res;
	}

	// 创建目标缓冲区
	res.resize(bufferSize - 1);

	// 执行实际转换
	int result = WideCharToMultiByte(
		CP_UTF8,
		0,
		wstr,
		-1,
		res.data(),
		bufferSize,
		nullptr,
		nullptr
	);

	return res;
}

std::vector<NameIP> GetIPv4BroadcastAddresses() {
	std::vector<NameIP> broadcastAddresses;

	ULONG size = 0;
	DWORD ret = GetAdaptersAddresses(AF_INET,
		GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
		NULL, NULL, &size);

	if (ret != ERROR_BUFFER_OVERFLOW) {
		return broadcastAddresses;
	}

	PIP_ADAPTER_ADDRESSES adapterAddrs = (PIP_ADAPTER_ADDRESSES)malloc(size);
	if (!adapterAddrs) {
		return broadcastAddresses;
	}

	ret = GetAdaptersAddresses(AF_INET,
		GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
		NULL, adapterAddrs, &size);

	if (ret != ERROR_SUCCESS) {
		free(adapterAddrs);
		return broadcastAddresses;
	}

	for (PIP_ADAPTER_ADDRESSES adapter = adapterAddrs; adapter != nullptr; adapter = adapter->Next) {
		PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;

		if (unicast->Address.lpSockaddr->sa_family != AF_INET) {
			continue;
		}

		SOCKADDR_IN* sockaddr = (SOCKADDR_IN*)unicast->Address.lpSockaddr;
		ULONG prefixLength = unicast->OnLinkPrefixLength;

		// 计算子网掩码
		ULONG mask = 0xFFFFFFFF;
		if (prefixLength > 0 && prefixLength <= 32) {
			mask = htonl(mask << (32 - prefixLength));
		}

		// 计算广播地址
		ULONG ip = sockaddr->sin_addr.S_un.S_addr;
		ULONG network = ip & mask;
		ULONG broadcast = network | (~mask);

		// 转换为字符串
		IN_ADDR addr;
		addr.S_un.S_addr = ip;

		char buffer[INET_ADDRSTRLEN] = { 0 };
		if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer))) {
			broadcastAddresses.emplace_back(convert_wstring_to_string(adapter->FriendlyName), buffer);
		}
	}

	free(adapterAddrs);
	return broadcastAddresses;
}
