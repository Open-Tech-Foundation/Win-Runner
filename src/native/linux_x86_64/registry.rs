//! Windows import-name registration and trampoline selection.

use super::*;

/// The name of an export that a DLL publishes by ordinal only, for the
/// ordinals winrun implements. Ordinals are per DLL, so they cannot share
/// [`baseline_trampoline`]'s global names.
pub(super) fn ordinal_export_name(dll: &str, func: &str) -> Option<&'static str> {
    let module = dll.to_ascii_uppercase();
    match (module.trim_end_matches(".DLL"), func) {
        ("OLEAUT32", "#200") => Some("GetErrorInfo"),
        ("OLEAUT32", "#201") => Some("SetErrorInfo"),
        _ => None,
    }
}

pub(in crate::native) fn supports_import(dll: &str, func: &str) -> bool {
    if let Some(name) = ordinal_export_name(dll, func) {
        return supports_import(dll, name);
    }
    let module = dll.to_ascii_uppercase();
    let module = if module.starts_with("API-MS-WIN-CRT-") {
        "UCRTBASE.DLL"
    } else if module.starts_with("API-MS-WIN-CORE-") || module.starts_with("EXT-MS-WIN-KERNEL32-") {
        "KERNEL32.DLL"
    } else if module.starts_with("API-MS-WIN-SECURITY-")
        || module.starts_with("EXT-MS-WIN-ADVAPI32-")
    {
        "ADVAPI32.DLL"
    } else {
        module.as_str()
    };
    let allowed = match module {
        "MSVCRT.DLL" | "UCRTBASE.DLL" => {
            matches!(
                func,
                "__set_app_type"
                    | "__lconv_init"
                    | "setlocale"
                    | "_fmode"
                    | "_commode"
                    | "__p__fmode"
                    | "__p__commode"
                    | "_acmdln"
                    | "_wcmdln"
                    | "_initterm"
                    | "_initterm_e"
                    | "_set_app_type"
                    | "_set_fmode"
                    | "__setusermatherr"
                    | "_register_thread_local_exe_atexit_callback"
                    | "_seh_filter_dll"
                    | "abort"
                    | "terminate"
                    | "_invoke_watson"
                    | "__getmainargs"
                    | "_configure_narrow_argv"
                    | "_configure_wide_argv"
                    | "_initialize_narrow_environment"
                    | "_initialize_wide_environment"
                    | "__p___argc"
                    | "__p___argv"
                    | "__p___wargv"
                    | "__p__acmdln"
                    | "__p__wcmdln"
                    | "__p___initenv"
                    | "__p___winitenv"
                    | "__p__pgmptr"
                    | "__p__wpgmptr"
                    | "_get_initial_narrow_environment"
                    | "_get_initial_wide_environment"
                    | "__p__environ"
                    | "__p__wenviron"
                    | "_crt_atexit"
                    | "_register_onexit_function"
                    | "_initialize_onexit_table"
                    | "_execute_onexit_table"
                    | "_set_new_mode"
                    | "_configthreadlocale"
                    | "_seh_filter_exe"
                    | "exit"
                    | "_exit"
                    | "_cexit"
                    | "_c_exit"
                    | "_onexit"
                    | "malloc"
                    | "realloc"
                    | "free"
                    | "memcmp"
                    | "memcpy"
                    | "memmove"
                    | "memset"
                    | "strlen"
                    | "_strdup"
                    | "strcmp"
                    | "strncmp"
                    | "strchr"
                    | "strrchr"
                    | "strstr"
                    | "_stricmp"
                    | "_strnicmp"
                    | "_errno"
                    | "_beginthreadex"
                    | "_fileno"
                    | "___mb_cur_max_l_func"
                    | "mbrtowc"
                    | "mbrlen"
                    | "mbsrtowcs"
                    | "wcrtomb"
                    | "wcrtomb_s"
                    | "isalnum"
                    | "isprint"
                    | "strcpy"
                    | "strcat"
                    | "strtof"
                    | "_strtod_l"
                    | "_strtold_l"
                    | "_strtof_l"
                    | "_wtoi64"
                    | "_aligned_malloc"
                    | "_aligned_free"
                    | "_msize"
                    | "bsearch"
                    | "div"
                    | "rand_s"
                    | "strerror_s"
                    | "feclearexcept"
                    | "_wassert"
                    | "setvbuf"
                    | "setbuf"
                    | "_setmode"
                    | "_dsign"
                    | "_fdsign"
                    | "exp2"
                    | "frexp"
                    | "ldexp"
                    | "log1p"
                    | "nearbyint"
                    | "nearbyintf"
                    | "nextafter"
                    | "nextafterf"
                    | "_localtime64_s"
                    | "localtime_s"
                    | "_tzset"
                    | "__timezone"
                    | "__tzname"
                    | "_strftime_l"
                    | "strftime"
                    | "mbtowc"
                    | "_mbtowc_l"
                    | "_write"
                    | "getenv"
                    | "_wgetenv"
                    | "_putenv"
                    | "_wputenv"
                    | "__iob_func"
                    | "__acrt_iob_func"
                    | "__stdio_common_vfprintf"
                    | "__stdio_common_vsprintf"
                    | "__stdio_common_vswprintf"
                    | "__stdio_common_vsnwprintf_s"
                    | "__stdio_common_vsnprintf_s"
                    | "__stdio_common_vfwprintf"
                    | "fputwc"
                    | "_create_locale"
                    | "_free_locale"
                    | "___lc_codepage_func"
                    | "___mb_cur_max_func"
                    | "___lc_locale_name_func"
                    | "__pctype_func"
                    | "_lock_locales"
                    | "_unlock_locales"
                    | "_gmtime64_s"
                    | "gmtime_s"
                    | "wcsftime"
                    | "_controlfp_s"
                    | "_callnewh"
                    | "_invalid_parameter_noinfo"
                    | "acos"
                    | "acosf"
                    | "acosh"
                    | "acoshf"
                    | "asin"
                    | "asinf"
                    | "asinh"
                    | "asinhf"
                    | "atan"
                    | "atanf"
                    | "atanh"
                    | "atanhf"
                    | "cbrt"
                    | "cbrtf"
                    | "ceil"
                    | "ceilf"
                    | "cos"
                    | "cosf"
                    | "cosh"
                    | "coshf"
                    | "exp"
                    | "expf"
                    | "floor"
                    | "floorf"
                    | "log"
                    | "logf"
                    | "log10"
                    | "log10f"
                    | "log2"
                    | "log2f"
                    | "sin"
                    | "sinf"
                    | "sinh"
                    | "sinhf"
                    | "sqrt"
                    | "sqrtf"
                    | "tan"
                    | "tanf"
                    | "tanh"
                    | "tanhf"
                    | "round"
                    | "roundf"
                    | "trunc"
                    | "truncf"
                    | "atan2"
                    | "atan2f"
                    | "pow"
                    | "powf"
                    | "fmod"
                    | "fmodf"
                    | "fma"
                    | "fmaf"
                    | "modf"
                    | "modff"
                    | "strtoul"
                    | "strtoull"
                    | "wcstoul"
                    | "_wcstoui64"
                    | "wcstoull"
                    | "_wtoi"
                    | "_wtol"
                    | "atol"
                    | "_atoi64"
                    | "_ltow_s"
                    | "strnlen"
                    | "wcsnlen"
                    | "_wcsdup"
                    | "strcpy_s"
                    | "strcat_s"
                    | "strncpy_s"
                    | "strncat_s"
                    | "wcscpy_s"
                    | "wcscat_s"
                    | "wcsncpy_s"
                    | "wcsncat_s"
                    | "_wcsicmp"
                    | "_wcsnicmp"
                    | "strtok_s"
                    | "isalpha"
                    | "isdigit"
                    | "isspace"
                    | "iswspace"
                    | "iswupper"
                    | "iswascii"
                    | "towlower"
                    | "towupper"
                    | "__stdio_common_vsprintf_s"
                    | "__stdio_common_vswprintf_s"
                    | "atoi"
                    | "strtol"
                    | "strtod"
                    | "qsort"
                    | "_time64"
                    | "signal"
                    | "tolower"
                    | "toupper"
                    | "strncpy"
                    | "mbstowcs"
                    | "wcstombs"
                    | "_stat64"
                    | "_wstat64"
                    | "_access"
                    | "_waccess"
                    | "_wremove"
                    | "_wrename"
                    | "calloc"
                    | "fopen"
                    | "_wfopen"
                    | "fread"
                    | "fclose"
                    | "feof"
                    | "ferror"
                    | "clearerr"
                    | "fgetc"
                    | "getc"
                    | "ungetc"
                    | "fgets"
                    | "getchar"
                    | "putchar"
                    | "puts"
                    | "printf"
                    | "fprintf"
                    | "fseek"
                    | "_fseeki64"
                    | "ftell"
                    | "_ftelli64"
                    | "rewind"
                    | "fwrite"
                    | "sprintf"
                    | "wcscmp"
                    | "wcslen"
                    | "wcsncmp"
                    | "wcschr"
                    | "wcsrchr"
                    | "wcscpy"
                    | "wcsncpy"
                    | "wcscat"
                    | "wcsncat"
                    | "wcsstr"
                    | "fflush"
                    | "fputs"
                    | "fputc"
                    | "_iob"
                    | "__initenv"
                    | "__winitenv"
                    | "_isatty"
                    | "_get_osfhandle"
            )
        }
        "VCRUNTIME140.DLL" => {
            matches!(
                func,
                "memcmp"
                    | "memcpy"
                    | "memmove"
                    | "memset"
                    | "strlen"
                    | "strchr"
                    | "strrchr"
                    | "strstr"
                    | "memchr"
                    | "__std_type_info_compare"
                    | "__std_exception_copy"
                    | "__std_exception_destroy"
                    | "__std_terminate"
                    | "_purecall"
                    | "__uncaught_exceptions"
                    | "__current_exception"
                    | "__current_exception_context"
            )
        }
        "WINMM.DLL" => func == "timeGetTime",
        "USERENV.DLL" => func == "GetUserProfileDirectoryW",
        "BCRYPTPRIMITIVES.DLL" => func == "ProcessPrng",
        "OLE32.DLL" => matches!(
            func,
            "CoInitialize"
                | "CoInitializeEx"
                | "CoUninitialize"
                | "CoTaskMemAlloc"
                | "CoTaskMemFree"
                | "CoCreateGuid"
                | "CoGetContextToken"
        ),
        "SHELL32.DLL" => func == "SHGetFolderPathW",
        "OLEAUT32.DLL" => matches!(func, "GetErrorInfo" | "SetErrorInfo"),
        "ADVAPI32.DLL" => matches!(
            func,
            "CryptAcquireContextW"
                | "CryptGenRandom"
                | "CryptReleaseContext"
                | "SystemFunction036"
                | "EventRegister"
                | "EventUnregister"
                | "EventSetInformation"
                | "EventWriteTransfer"
                | "RegOpenKeyExA"
                | "RegOpenKeyExW"
                | "RegCreateKeyExW"
                | "RegSetValueExW"
                | "RegQueryValueExW"
                | "RegGetValueW"
                | "RegDeleteValueW"
                | "RegDeleteKeyW"
                | "RegDeleteTreeW"
                | "RegEnumKeyExW"
                | "RegEnumValueW"
                | "RegQueryInfoKeyW"
                | "RegCloseKey"
                | "OpenThreadToken"
                | "RevertToSelf"
                | "SetThreadToken"
                | "GetTokenInformation"
                | "GetSidSubAuthorityCount"
                | "GetSidSubAuthority"
                | "RegisterEventSourceW"
                | "ReportEventW"
                | "DeregisterEventSource"
                | "EventWrite"
                | "LookupPrivilegeValueW"
                | "AdjustTokenPrivileges"
                | "OpenProcessToken"
                | "GetUserNameW"
        ),
        "WS2_32.DLL" => matches!(
            func,
            "#2" | "#3"
                | "#4"
                | "#13"
                | "#19"
                | "#22"
                | "#5"
                | "#6"
                | "#21"
                | "#7"
                | "#11"
                | "#10"
                | "#8"
                | "#9"
                | "#14"
                | "#15"
                | "#23"
                | "#57"
                | "GetAddrInfoW"
                | "FreeAddrInfoW"
                | "#111"
                | "#112"
                | "#115"
                | "#116"
                | "WSAIoctl"
                | "WSARecv"
                | "WSASend"
                | "listen"
        ),
        "USER32.DLL" => matches!(func, "GetSystemMetrics" | "MessageBeep" | "LoadStringW"),
        "IPHLPAPI.DLL" => func == "GetAdaptersAddresses",
        "NTDLL.DLL" => matches!(
            func,
            "RtlAddFunctionTable"
                | "RtlCaptureContext"
                | "RtlDeleteFunctionTable"
                | "RtlDispatchException"
                | "RtlLookupFunctionEntry"
                | "RtlRaiseException"
                | "RtlRestoreContext"
                | "RtlAddGrowableFunctionTable"
                | "RtlGrowFunctionTable"
                | "RtlDeleteGrowableFunctionTable"
                | "RtlUnwind"
                | "RtlUnwindEx"
                | "RtlVirtualUnwind"
                | "RtlGetVersion"
                | "RtlNtStatusToDosError"
                | "NtReadFile"
                | "NtWriteFile"
        ),
        "KERNEL32.DLL" | "KERNELBASE.DLL" => {
            !func.starts_with('#')
                && !matches!(
                    func,
                    "timeGetTime" | "GetUserProfileDirectoryW" | "ProcessPrng"
                )
        }
        _ => false,
    };
    allowed
        && !(module == "MSVCRT.DLL"
            && matches!(
                func,
                "__acrt_iob_func"
                    | "__stdio_common_vfprintf"
                    | "__stdio_common_vsprintf"
                    | "__stdio_common_vswprintf"
            ))
        && baseline_trampoline(func).is_some()
}

pub(super) fn baseline_trampoline(name: &str) -> Option<u64> {
    match name {
        "__set_app_type" => Some(native_crt_set_app_type as *const () as usize as u64),
        "__p__fmode" => Some(native_crt_p_fmode as *const () as usize as u64),
        "__p__commode" => Some(native_crt_p_commode as *const () as usize as u64),
        "_errno" => Some(native_crt_errno as *const () as usize as u64),
        "mbtowc" => Some(native_crt_mbtowc as *const () as usize as u64),
        "_mbtowc_l" => Some(native_crt_mbtowc_l as *const () as usize as u64),
        "___mb_cur_max_l_func" => Some(native_crt_mb_cur_max_l as *const () as usize as u64),
        "mbrtowc" => Some(native_crt_mbrtowc as *const () as usize as u64),
        "mbrlen" => Some(native_crt_mbrlen as *const () as usize as u64),
        "mbsrtowcs" => Some(native_crt_mbsrtowcs as *const () as usize as u64),
        "wcrtomb" => Some(native_crt_wcrtomb as *const () as usize as u64),
        "wcrtomb_s" => Some(native_crt_wcrtomb_s as *const () as usize as u64),
        "isalnum" => Some(native_crt_isalnum as *const () as usize as u64),
        "isprint" => Some(native_crt_isprint as *const () as usize as u64),
        "strcpy" => Some(native_crt_strcpy as *const () as usize as u64),
        "strcat" => Some(native_crt_strcat as *const () as usize as u64),
        "strtof" => Some(native_crt_strtof as *const () as usize as u64),
        "_strtod_l" => Some(native_crt_strtod_l as *const () as usize as u64),
        "_strtold_l" => Some(native_crt_strtod_l as *const () as usize as u64),
        "_strtof_l" => Some(native_crt_strtof_l as *const () as usize as u64),
        "_wtoi64" => Some(native_crt_wtoi64 as *const () as usize as u64),
        "_aligned_malloc" => Some(native_crt_aligned_malloc as *const () as usize as u64),
        "_aligned_free" => Some(native_crt_aligned_free as *const () as usize as u64),
        "_msize" => Some(native_crt_msize as *const () as usize as u64),
        "bsearch" => Some(native_crt_bsearch as *const () as usize as u64),
        "div" => Some(native_crt_div as *const () as usize as u64),
        "rand_s" => Some(native_crt_rand_s as *const () as usize as u64),
        "strerror_s" => Some(native_crt_strerror_s as *const () as usize as u64),
        "feclearexcept" => Some(native_crt_feclearexcept as *const () as usize as u64),
        "_wassert" => Some(native_crt_wassert as *const () as usize as u64),
        "setvbuf" => Some(native_crt_setvbuf as *const () as usize as u64),
        "setbuf" => Some(native_crt_setbuf as *const () as usize as u64),
        "_setmode" => Some(native_crt_setmode as *const () as usize as u64),
        "_dsign" => Some(native_crt_dsign as *const () as usize as u64),
        "_fdsign" => Some(native_crt_fdsign as *const () as usize as u64),
        "exp2" => Some(native_crt_exp2 as *const () as usize as u64),
        "frexp" => Some(native_crt_frexp as *const () as usize as u64),
        "ldexp" => Some(native_crt_ldexp as *const () as usize as u64),
        "log1p" => Some(native_crt_log1p as *const () as usize as u64),
        "nearbyint" => Some(native_crt_nearbyint as *const () as usize as u64),
        "nearbyintf" => Some(native_crt_nearbyintf as *const () as usize as u64),
        "nextafter" => Some(native_crt_nextafter as *const () as usize as u64),
        "nextafterf" => Some(native_crt_nextafterf as *const () as usize as u64),
        "_localtime64_s" => Some(native_crt_localtime64_s as *const () as usize as u64),
        "localtime_s" => Some(native_crt_localtime64_s as *const () as usize as u64),
        "_tzset" => Some(native_crt_tzset as *const () as usize as u64),
        "__timezone" => Some(native_crt_timezone as *const () as usize as u64),
        "__tzname" => Some(native_crt_tzname as *const () as usize as u64),
        "_strftime_l" => Some(native_crt_strftime_l as *const () as usize as u64),
        "strftime" => Some(native_crt_strftime as *const () as usize as u64),
        "memchr" => Some(native_crt_memchr as *const () as usize as u64),
        "__std_type_info_compare" => Some(native_std_type_info_compare as *const () as usize as u64),
        "__std_exception_copy" => Some(native_std_exception_copy as *const () as usize as u64),
        "__std_exception_destroy" => Some(native_std_exception_destroy as *const () as usize as u64),
        "__std_terminate" => Some(native_std_terminate as *const () as usize as u64),
        "_purecall" => Some(native_crt_purecall as *const () as usize as u64),
        "__uncaught_exceptions" => Some(native_crt_uncaught_exceptions as *const () as usize as u64),
        "__current_exception" => Some(native_current_exception as *const () as usize as u64),
        "__current_exception_context" => Some(native_current_exception_context as *const () as usize as u64),
        "_fileno" => Some(native_crt_fileno as *const () as usize as u64),
        "_beginthreadex" => Some(native_crt_beginthreadex as *const () as usize as u64),
        "getenv" => Some(native_crt_getenv as *const () as usize as u64),
        "_wgetenv" => Some(native_crt_wgetenv as *const () as usize as u64),
        "_putenv" => Some(native_crt_putenv as *const () as usize as u64),
        "_wputenv" => Some(native_crt_wputenv as *const () as usize as u64),
        "__iob_func" => Some(native_crt_iob_func as *const () as usize as u64),
        "__acrt_iob_func" => Some(native_crt_acrt_iob_func as *const () as usize as u64),
        "__stdio_common_vfprintf" => {
            Some(native_crt_stdio_common_vfprintf as *const () as usize as u64)
        }
        "__stdio_common_vsprintf" => {
            Some(native_crt_stdio_common_vsprintf as *const () as usize as u64)
        }
        "__stdio_common_vswprintf" => {
            Some(native_crt_stdio_common_vswprintf as *const () as usize as u64)
        }
        "__lconv_init" => Some(native_crt_lconv_init as *const () as usize as u64),
        "setlocale" => Some(native_crt_setlocale as *const () as usize as u64),
        "_initterm" => Some(native_crt_initterm as *const () as usize as u64),
        "strtoul" => Some(native_crt_strtoul as *const () as usize as u64),
        "strtoull" => Some(native_crt_strtoull as *const () as usize as u64),
        "wcstoul" => Some(native_crt_wcstoul as *const () as usize as u64),
        "_wcstoui64" => Some(native_crt_wcstoui64 as *const () as usize as u64),
        "wcstoull" => Some(native_crt_wcstoui64 as *const () as usize as u64),
        "_wtoi" => Some(native_crt_wtoi as *const () as usize as u64),
        "_wtol" => Some(native_crt_wtoi as *const () as usize as u64),
        "atol" => Some(native_crt_atol as *const () as usize as u64),
        "_atoi64" => Some(native_crt_atoi64 as *const () as usize as u64),
        "_ltow_s" => Some(native_crt_ltow_s as *const () as usize as u64),
        "strnlen" => Some(native_crt_strnlen as *const () as usize as u64),
        "wcsnlen" => Some(native_crt_wcsnlen as *const () as usize as u64),
        "_wcsdup" => Some(native_crt_wcsdup as *const () as usize as u64),
        "strcpy_s" => Some(native_crt_strcpy_s as *const () as usize as u64),
        "strcat_s" => Some(native_crt_strcat_s as *const () as usize as u64),
        "strncpy_s" => Some(native_crt_strncpy_s as *const () as usize as u64),
        "strncat_s" => Some(native_crt_strncat_s as *const () as usize as u64),
        "wcscpy_s" => Some(native_crt_wcscpy_s as *const () as usize as u64),
        "wcscat_s" => Some(native_crt_wcscat_s as *const () as usize as u64),
        "wcsncpy_s" => Some(native_crt_wcsncpy_s as *const () as usize as u64),
        "wcsncat_s" => Some(native_crt_wcsncat_s as *const () as usize as u64),
        "_wcsicmp" => Some(native_crt_wcsicmp as *const () as usize as u64),
        "_wcsnicmp" => Some(native_crt_wcsnicmp as *const () as usize as u64),
        "strtok_s" => Some(native_crt_strtok_s as *const () as usize as u64),
        "isalpha" => Some(native_crt_isalpha as *const () as usize as u64),
        "isdigit" => Some(native_crt_isdigit as *const () as usize as u64),
        "isspace" => Some(native_crt_isspace as *const () as usize as u64),
        "iswspace" => Some(native_crt_iswspace as *const () as usize as u64),
        "iswupper" => Some(native_crt_iswupper as *const () as usize as u64),
        "iswascii" => Some(native_crt_iswascii as *const () as usize as u64),
        "towlower" => Some(native_crt_towlower as *const () as usize as u64),
        "towupper" => Some(native_crt_towupper as *const () as usize as u64),
        "acos" => Some(native_crt_acos as *const () as usize as u64),
        "acosf" => Some(native_crt_acosf as *const () as usize as u64),
        "acosh" => Some(native_crt_acosh as *const () as usize as u64),
        "acoshf" => Some(native_crt_acoshf as *const () as usize as u64),
        "asin" => Some(native_crt_asin as *const () as usize as u64),
        "asinf" => Some(native_crt_asinf as *const () as usize as u64),
        "asinh" => Some(native_crt_asinh as *const () as usize as u64),
        "asinhf" => Some(native_crt_asinhf as *const () as usize as u64),
        "atan" => Some(native_crt_atan as *const () as usize as u64),
        "atanf" => Some(native_crt_atanf as *const () as usize as u64),
        "atanh" => Some(native_crt_atanh as *const () as usize as u64),
        "atanhf" => Some(native_crt_atanhf as *const () as usize as u64),
        "cbrt" => Some(native_crt_cbrt as *const () as usize as u64),
        "cbrtf" => Some(native_crt_cbrtf as *const () as usize as u64),
        "ceil" => Some(native_crt_ceil as *const () as usize as u64),
        "ceilf" => Some(native_crt_ceilf as *const () as usize as u64),
        "cos" => Some(native_crt_cos as *const () as usize as u64),
        "cosf" => Some(native_crt_cosf as *const () as usize as u64),
        "cosh" => Some(native_crt_cosh as *const () as usize as u64),
        "coshf" => Some(native_crt_coshf as *const () as usize as u64),
        "exp" => Some(native_crt_exp as *const () as usize as u64),
        "expf" => Some(native_crt_expf as *const () as usize as u64),
        "floor" => Some(native_crt_floor as *const () as usize as u64),
        "floorf" => Some(native_crt_floorf as *const () as usize as u64),
        "log" => Some(native_crt_log as *const () as usize as u64),
        "logf" => Some(native_crt_logf as *const () as usize as u64),
        "log10" => Some(native_crt_log10 as *const () as usize as u64),
        "log10f" => Some(native_crt_log10f as *const () as usize as u64),
        "log2" => Some(native_crt_log2 as *const () as usize as u64),
        "log2f" => Some(native_crt_log2f as *const () as usize as u64),
        "sin" => Some(native_crt_sin as *const () as usize as u64),
        "sinf" => Some(native_crt_sinf as *const () as usize as u64),
        "sinh" => Some(native_crt_sinh as *const () as usize as u64),
        "sinhf" => Some(native_crt_sinhf as *const () as usize as u64),
        "sqrt" => Some(native_crt_sqrt as *const () as usize as u64),
        "sqrtf" => Some(native_crt_sqrtf as *const () as usize as u64),
        "tan" => Some(native_crt_tan as *const () as usize as u64),
        "tanf" => Some(native_crt_tanf as *const () as usize as u64),
        "tanh" => Some(native_crt_tanh as *const () as usize as u64),
        "tanhf" => Some(native_crt_tanhf as *const () as usize as u64),
        "round" => Some(native_crt_round as *const () as usize as u64),
        "roundf" => Some(native_crt_roundf as *const () as usize as u64),
        "trunc" => Some(native_crt_trunc as *const () as usize as u64),
        "truncf" => Some(native_crt_truncf as *const () as usize as u64),
        "atan2" => Some(native_crt_atan2 as *const () as usize as u64),
        "atan2f" => Some(native_crt_atan2f as *const () as usize as u64),
        "pow" => Some(native_crt_pow as *const () as usize as u64),
        "powf" => Some(native_crt_powf as *const () as usize as u64),
        "fmod" => Some(native_crt_fmod as *const () as usize as u64),
        "fmodf" => Some(native_crt_fmodf as *const () as usize as u64),
        "fma" => Some(native_crt_fma as *const () as usize as u64),
        "fmaf" => Some(native_crt_fmaf as *const () as usize as u64),
        "modf" => Some(native_crt_modf as *const () as usize as u64),
        "modff" => Some(native_crt_modff as *const () as usize as u64),
        "GetActiveProcessorGroupCount" => Some(native_get_active_processor_group_count as *const () as usize as u64),
        "GetProcessGroupAffinity" => Some(native_get_process_group_affinity as *const () as usize as u64),
        "GetThreadGroupAffinity" => Some(native_get_thread_group_affinity as *const () as usize as u64),
        "SetThreadGroupAffinity" => Some(native_set_thread_group_affinity as *const () as usize as u64),
        "SetThreadAffinityMask" => Some(native_set_thread_affinity_mask as *const () as usize as u64),
        "GetCurrentProcessorNumberEx" => Some(native_get_current_processor_number_ex as *const () as usize as u64),
        "GetThreadIdealProcessorEx" => Some(native_get_thread_ideal_processor_ex as *const () as usize as u64),
        "SetThreadIdealProcessorEx" => Some(native_set_thread_ideal_processor_ex as *const () as usize as u64),
        "GetNumaHighestNodeNumber" => Some(native_get_numa_highest_node_number as *const () as usize as u64),
        "GetNumaProcessorNodeEx" => Some(native_get_numa_processor_node_ex as *const () as usize as u64),
        "GetLogicalProcessorInformationEx" => Some(native_get_logical_processor_information_ex as *const () as usize as u64),
        "GetSystemDefaultLCID" => Some(native_get_default_lcid as *const () as usize as u64),
        "GetUserDefaultLCID" => Some(native_get_default_lcid as *const () as usize as u64),
        "GetThreadLocale" => Some(native_get_default_lcid as *const () as usize as u64),
        "GetUserDefaultLocaleName" => Some(native_get_user_default_locale_name as *const () as usize as u64),
        "GetThreadPriority" => Some(native_get_thread_priority as *const () as usize as u64),
        "SetThreadPriority" => Some(native_set_thread_priority as *const () as usize as u64),
        "SetThreadErrorMode" => Some(native_set_thread_error_mode as *const () as usize as u64),
        "SleepEx" => Some(native_sleep_ex as *const () as usize as u64),
        "WaitForSingleObjectEx" => Some(native_wait_for_single_object_ex as *const () as usize as u64),
        "CreateSemaphoreW" => Some(native_create_semaphore_w as *const () as usize as u64),
        "CreateSemaphoreExW" => Some(native_create_semaphore_ex_w as *const () as usize as u64),
        "HeapCreate" => Some(native_heap_create as *const () as usize as u64),
        "HeapDestroy" => Some(native_heap_destroy as *const () as usize as u64),
        "GetLargePageMinimum" => Some(native_get_large_page_minimum as *const () as usize as u64),
        "VirtualUnlock" => Some(native_virtual_unlock as *const () as usize as u64),
        "FlushProcessWriteBuffers" => Some(native_flush_process_write_buffers as *const () as usize as u64),
        "FlushInstructionCache" => Some(native_flush_instruction_cache as *const () as usize as u64),
        "GetFileSize" => Some(native_get_file_size as *const () as usize as u64),
        "IsProcessInJob" => Some(native_is_process_in_job as *const () as usize as u64),
        "GetEnabledXStateFeatures" => Some(native_get_enabled_xstate_features as *const () as usize as u64),
        "LocateXStateFeature" => Some(native_locate_xstate_feature as *const () as usize as u64),
        "SetXStateFeaturesMask" => Some(native_set_xstate_features_mask as *const () as usize as u64),
        "InitializeContext" => Some(native_initialize_context as *const () as usize as u64),
        "CopyContext" => Some(native_copy_context as *const () as usize as u64),
        "RtlPcToFileHeader" => Some(native_rtl_pc_to_file_header as *const () as usize as u64),
        "RtlInstallFunctionTableCallback" => Some(native_rtl_install_function_table_callback as *const () as usize as u64),
        "WerRegisterRuntimeExceptionModule" => Some(native_wer_register_runtime_exception_module as *const () as usize as u64),
        "UnhandledExceptionFilter" => Some(native_unhandled_exception_filter as *const () as usize as u64),
        "RaiseFailFastException" => Some(native_raise_fail_fast_exception as *const () as usize as u64),
        "DebugBreak" => Some(native_debug_break as *const () as usize as u64),
        "RegisterEventSourceW" => Some(native_register_event_source_w as *const () as usize as u64),
        "ReportEventW" => Some(native_report_event_w as *const () as usize as u64),
        "DeregisterEventSource" => Some(native_deregister_event_source as *const () as usize as u64),
        "EventWrite" => Some(native_event_write as *const () as usize as u64),
        "CoInitializeEx" => Some(native_co_initialize_ex as *const () as usize as u64),
        "CoGetContextToken" => Some(native_co_get_context_token as *const () as usize as u64),
        "IsThreadAFiber" => Some(native_is_thread_a_fiber as *const () as usize as u64),
        "DisableThreadLibraryCalls" => Some(native_disable_thread_library_calls as *const () as usize as u64),
        "GetErrorInfo" => Some(native_get_error_info as *const () as usize as u64),
        "SetErrorInfo" => Some(native_set_error_info as *const () as usize as u64),
        "RoInitialize" => Some(native_ro_initialize as *const () as usize as u64),
        "RoUninitialize" => Some(native_co_uninitialize as *const () as usize as u64),
        "SetThreadDescription" => Some(native_set_thread_description as *const () as usize as u64),
        "CoUninitialize" => Some(native_co_uninitialize as *const () as usize as u64),
        "CoTaskMemAlloc" => Some(native_co_task_mem_alloc as *const () as usize as u64),
        "CoTaskMemFree" => Some(native_co_task_mem_free as *const () as usize as u64),
        "CoCreateGuid" => Some(native_co_create_guid as *const () as usize as u64),
        "LoadStringW" => Some(native_load_string_w as *const () as usize as u64),
        "_controlfp_s" => Some(native_crt_controlfp_s as *const () as usize as u64),
        "_callnewh" => Some(native_crt_callnewh as *const () as usize as u64),
        "_invalid_parameter_noinfo" => Some(native_crt_invalid_parameter_noinfo as *const () as usize as u64),
        "CreateMemoryResourceNotification" => {
            Some(native_create_memory_resource_notification as *const () as usize as u64)
        }
        "QueryMemoryResourceNotification" => {
            Some(native_query_memory_resource_notification as *const () as usize as u64)
        }
        "OpenThreadToken" => Some(native_open_thread_token as *const () as usize as u64),
        "RevertToSelf" => Some(native_revert_to_self as *const () as usize as u64),
        "SetThreadToken" => Some(native_set_thread_token as *const () as usize as u64),
        "GetTokenInformation" => Some(native_get_token_information as *const () as usize as u64),
        "GetSidSubAuthorityCount" => Some(native_get_sid_sub_authority_count as *const () as usize as u64),
        "GetSidSubAuthority" => Some(native_get_sid_sub_authority as *const () as usize as u64),
        "WaitForMultipleObjects" => {
            Some(native_wait_for_multiple_objects as *const () as usize as u64)
        }
        "WaitForMultipleObjectsEx" => {
            Some(native_wait_for_multiple_objects_ex as *const () as usize as u64)
        }
        "SignalObjectAndWait" => Some(native_signal_object_and_wait as *const () as usize as u64),
        "OpenEventW" => Some(native_open_event_w as *const () as usize as u64),
        "QueryInformationJobObject" => {
            Some(native_query_information_job_object as *const () as usize as u64)
        }
        "_gmtime64_s" => Some(native_crt_gmtime64_s as *const () as usize as u64),
        "gmtime_s" => Some(native_crt_gmtime64_s as *const () as usize as u64),
        "wcsftime" => Some(native_crt_wcsftime as *const () as usize as u64),
        "_create_locale" => Some(native_crt_create_locale as *const () as usize as u64),
        "_free_locale" => Some(native_crt_free_locale as *const () as usize as u64),
        "___lc_codepage_func" => Some(native_crt_lc_codepage as *const () as usize as u64),
        "___mb_cur_max_func" => Some(native_crt_mb_cur_max as *const () as usize as u64),
        "___lc_locale_name_func" => Some(native_crt_lc_locale_name as *const () as usize as u64),
        "__pctype_func" => Some(native_crt_pctype as *const () as usize as u64),
        "_lock_locales" => Some(native_crt_lock_locales as *const () as usize as u64),
        "_unlock_locales" => Some(native_crt_lock_locales as *const () as usize as u64),
        "__stdio_common_vfwprintf" => Some(native_crt_stdio_common_vfwprintf as *const () as usize as u64),
        "fputwc" => Some(native_crt_fputwc as *const () as usize as u64),
        "__stdio_common_vsnprintf_s" => {
            Some(native_crt_stdio_common_vsnprintf_s as *const () as usize as u64)
        }
        "__stdio_common_vsnwprintf_s" => {
            Some(native_crt_stdio_common_vsnwprintf_s as *const () as usize as u64)
        }
        "__stdio_common_vsprintf_s" => {
            Some(native_crt_stdio_common_vsprintf_s as *const () as usize as u64)
        }
        "__stdio_common_vswprintf_s" => {
            Some(native_crt_stdio_common_vswprintf_s as *const () as usize as u64)
        }
        "_initterm_e" => Some(native_crt_initterm_e as *const () as usize as u64),
        "_set_app_type" => Some(native_crt_set_app_type as *const () as usize as u64),
        "_set_fmode" => Some(native_crt_set_fmode as *const () as usize as u64),
        "__setusermatherr" => Some(native_crt_set_user_math_err as *const () as usize as u64),
        "_register_thread_local_exe_atexit_callback" => {
            Some(native_crt_register_thread_local_exe_atexit_callback as *const () as usize as u64)
        }
        "_seh_filter_dll" => Some(native_crt_seh_filter as *const () as usize as u64),
        "abort" => Some(native_crt_abort as *const () as usize as u64),
        "terminate" => Some(native_crt_abort as *const () as usize as u64),
        "_invoke_watson" => Some(native_crt_invoke_watson as *const () as usize as u64),
        "__getmainargs" => Some(native_crt_getmainargs as *const () as usize as u64),
        "_configure_narrow_argv" => {
            Some(native_crt_configure_narrow_argv as *const () as usize as u64)
        }
        "_configure_wide_argv" => Some(native_crt_configure_wide_argv as *const () as usize as u64),
        "_initialize_narrow_environment" => {
            Some(native_crt_initialize_narrow_environment as *const () as usize as u64)
        }
        "_initialize_wide_environment" => {
            Some(native_crt_initialize_wide_environment as *const () as usize as u64)
        }
        "__p___argc" => Some(native_crt_p_argc as *const () as usize as u64),
        "__p___argv" => Some(native_crt_p_argv as *const () as usize as u64),
        "__p___wargv" => Some(native_crt_p_wargv as *const () as usize as u64),
        "__p__acmdln" => Some(native_crt_p_acmdln as *const () as usize as u64),
        "__p__wcmdln" => Some(native_crt_p_wcmdln as *const () as usize as u64),
        "__p__pgmptr" => Some(native_crt_p_pgmptr as *const () as usize as u64),
        "__p__wpgmptr" => Some(native_crt_p_wpgmptr as *const () as usize as u64),
        "__p___initenv" => Some(native_crt_p_initenv as *const () as usize as u64),
        "__p___winitenv" => Some(native_crt_p_winitenv as *const () as usize as u64),
        "_get_initial_narrow_environment" => {
            Some(native_crt_get_initial_narrow_environment as *const () as usize as u64)
        }
        "_get_initial_wide_environment" => {
            Some(native_crt_get_initial_wide_environment as *const () as usize as u64)
        }
        "__p__environ" => Some(native_crt_p_environ as *const () as usize as u64),
        "__p__wenviron" => Some(native_crt_p_wenviron as *const () as usize as u64),
        "_crt_atexit" => Some(native_crt_atexit as *const () as usize as u64),
        "_register_onexit_function" => {
            Some(native_crt_register_onexit_function as *const () as usize as u64)
        }
        "_initialize_onexit_table" => {
            Some(native_crt_initialize_onexit_table as *const () as usize as u64)
        }
        "_execute_onexit_table" => {
            Some(native_crt_execute_onexit_table as *const () as usize as u64)
        }
        "_set_new_mode" => Some(native_crt_set_new_mode as *const () as usize as u64),
        "_configthreadlocale" => Some(native_crt_config_thread_locale as *const () as usize as u64),
        "_seh_filter_exe" => Some(native_crt_seh_filter_exe as *const () as usize as u64),
        "exit" => Some(native_crt_exit as *const () as usize as u64),
        "_exit" => Some(native_exit_process as *const () as usize as u64),
        "_cexit" => Some(native_crt_cexit as *const () as usize as u64),
        "_c_exit" => Some(native_crt_c_exit as *const () as usize as u64),
        "_onexit" => Some(native_crt_onexit as *const () as usize as u64),
        "strlen" => Some(native_crt_strlen as *const () as usize as u64),
        "_strdup" => Some(native_crt_strdup as *const () as usize as u64),
        "strcmp" => Some(native_crt_strcmp as *const () as usize as u64),
        "strncmp" => Some(native_crt_strncmp as *const () as usize as u64),
        "strchr" => Some(native_crt_strchr as *const () as usize as u64),
        "strrchr" => Some(native_crt_strrchr as *const () as usize as u64),
        "strstr" => Some(native_crt_strstr as *const () as usize as u64),
        "_stricmp" => Some(native_crt_stricmp as *const () as usize as u64),
        "_strnicmp" => Some(native_crt_strnicmp as *const () as usize as u64),
        "atoi" => Some(native_crt_atoi as *const () as usize as u64),
        "strtol" => Some(native_crt_strtol as *const () as usize as u64),
        "strtod" => Some(native_crt_strtod as *const () as usize as u64),
        "qsort" => Some(native_crt_qsort as *const () as usize as u64),
        "_time64" => Some(native_crt_time64 as *const () as usize as u64),
        "signal" => Some(native_crt_signal as *const () as usize as u64),
        "tolower" => Some(native_crt_tolower as *const () as usize as u64),
        "toupper" => Some(native_crt_toupper as *const () as usize as u64),
        "strncpy" => Some(native_crt_strncpy as *const () as usize as u64),
        "mbstowcs" => Some(native_crt_mbstowcs as *const () as usize as u64),
        "wcstombs" => Some(native_crt_wcstombs as *const () as usize as u64),
        "_stat64" => Some(native_crt_stat64 as *const () as usize as u64),
        "_wstat64" => Some(native_crt_wstat64 as *const () as usize as u64),
        "_access" => Some(native_crt_access as *const () as usize as u64),
        "_waccess" => Some(native_crt_waccess as *const () as usize as u64),
        "_wremove" => Some(native_crt_wremove as *const () as usize as u64),
        "_wrename" => Some(native_crt_wrename as *const () as usize as u64),
        "calloc" => Some(native_crt_calloc as *const () as usize as u64),
        "fopen" => Some(native_crt_fopen as *const () as usize as u64),
        "_wfopen" => Some(native_crt_wfopen as *const () as usize as u64),
        "fread" => Some(native_crt_fread as *const () as usize as u64),
        "fclose" => Some(native_crt_fclose as *const () as usize as u64),
        "feof" => Some(native_crt_feof as *const () as usize as u64),
        "ferror" => Some(native_crt_ferror as *const () as usize as u64),
        "clearerr" => Some(native_crt_clearerr as *const () as usize as u64),
        "fgetc" | "getc" => Some(native_crt_fgetc as *const () as usize as u64),
        "ungetc" => Some(native_crt_ungetc as *const () as usize as u64),
        "fgets" => Some(native_crt_fgets as *const () as usize as u64),
        "getchar" => Some(native_crt_getchar as *const () as usize as u64),
        "putchar" => Some(native_crt_putchar as *const () as usize as u64),
        "puts" => Some(native_crt_puts as *const () as usize as u64),
        "printf" => Some(native_crt_printf as *const () as usize as u64),
        "fprintf" => Some(native_crt_fprintf as *const () as usize as u64),
        "fseek" => Some(native_crt_fseek as *const () as usize as u64),
        "_fseeki64" => Some(native_crt_fseeki64 as *const () as usize as u64),
        "ftell" => Some(native_crt_ftell as *const () as usize as u64),
        "_ftelli64" => Some(native_crt_ftelli64 as *const () as usize as u64),
        "rewind" => Some(native_crt_rewind as *const () as usize as u64),
        "fwrite" => Some(native_crt_fwrite as *const () as usize as u64),
        "sprintf" => Some(native_crt_sprintf as *const () as usize as u64),
        "wcscmp" => Some(native_crt_wcscmp as *const () as usize as u64),
        "wcslen" => Some(native_crt_wcslen as *const () as usize as u64),
        "wcsncmp" => Some(native_crt_wcsncmp as *const () as usize as u64),
        "wcschr" => Some(native_crt_wcschr as *const () as usize as u64),
        "wcsrchr" => Some(native_crt_wcsrchr as *const () as usize as u64),
        "wcscpy" => Some(native_crt_wcscpy as *const () as usize as u64),
        "wcsncpy" => Some(native_crt_wcsncpy as *const () as usize as u64),
        "wcscat" => Some(native_crt_wcscat as *const () as usize as u64),
        "wcsncat" => Some(native_crt_wcsncat as *const () as usize as u64),
        "wcsstr" => Some(native_crt_wcsstr as *const () as usize as u64),
        "fflush" => Some(native_crt_fflush as *const () as usize as u64),
        "fputs" => Some(native_crt_fputs as *const () as usize as u64),
        "fputc" => Some(native_crt_fputc as *const () as usize as u64),
        "_iob" => Some(NATIVE_CRT_IOB.as_ptr() as u64),
        "__initenv" => Some(NATIVE_CRT_INITENV.as_ptr() as u64),
        "__winitenv" => Some(NATIVE_CRT_WINITENV.as_ptr() as u64),
        "malloc" => Some(native_crt_malloc as *const () as usize as u64),
        "realloc" => Some(native_crt_realloc as *const () as usize as u64),
        "free" => Some(native_crt_free as *const () as usize as u64),
        "memcmp" => Some(native_crt_memcmp as *const () as usize as u64),
        "memcpy" => Some(native_crt_memcpy as *const () as usize as u64),
        "memmove" => Some(native_crt_memmove as *const () as usize as u64),
        "memset" => Some(native_crt_memset as *const () as usize as u64),
        // These MSVCRT exports are data, not callable functions. Their
        // IAT entries must point at writable storage because CRT startup
        // initializes them before invoking the executable entry point.
        "_fmode" => Some(NATIVE_CRT_FMODE.as_ptr() as u64),
        "_commode" => Some(NATIVE_CRT_COMMODE.as_ptr() as u64),
        "_acmdln" => Some(NATIVE_CRT_ACMDLN.as_ptr() as u64),
        "_wcmdln" => Some(NATIVE_CRT_WCMDLN.as_ptr() as u64),
        "RtlAddFunctionTable" => Some(native_rtl_add_function_table as *const () as usize as u64),
        "RtlCaptureContext" => Some(winrun_native_rtl_capture_context as *const () as usize as u64),
        "RtlDeleteFunctionTable" => {
            Some(native_rtl_delete_function_table as *const () as usize as u64)
        }
        "RtlDispatchException" => Some(native_rtl_dispatch_exception as *const () as usize as u64),
        "RtlLookupFunctionEntry" => {
            Some(native_rtl_lookup_function_entry as *const () as usize as u64)
        }
        "RtlVirtualUnwind" => Some(native_rtl_virtual_unwind as *const () as usize as u64),
        "RtlAddGrowableFunctionTable" => {
            Some(native_rtl_add_growable_function_table as *const () as usize as u64)
        }
        "RtlGrowFunctionTable" => Some(native_rtl_grow_function_table as *const () as usize as u64),
        "RtlDeleteGrowableFunctionTable" => {
            Some(native_rtl_delete_growable_function_table as *const () as usize as u64)
        }
        "RaiseException" => Some(winrun_native_raise_exception as *const () as usize as u64),
        "RtlUnwindEx" => Some(winrun_native_rtl_unwind_ex as *const () as usize as u64),
        "RtlUnwind" => Some(winrun_native_rtl_unwind as *const () as usize as u64),
        "RtlRestoreContext" => Some(native_rtl_restore_context as *const () as usize as u64),
        "RtlRaiseException" => Some(native_rtl_raise_exception as *const () as usize as u64),
        // Winsock's stable ordinal exports for byte-order conversion.
        "#8" | "#14" => Some(native_network_u32 as *const () as usize as u64),
        "#9" | "#15" => Some(native_network_u16 as *const () as usize as u64),
        "#10" => Some(native_ioctlsocket as *const () as usize as u64),
        "#11" => Some(native_wsa_inet_addr as *const () as usize as u64),
        "#4" => Some(native_connect_socket as *const () as usize as u64),
        "#2" => Some(native_bind_socket as *const () as usize as u64),
        "#13" | "listen" => Some(native_listen_socket as *const () as usize as u64),
        "#19" => Some(native_send_socket as *const () as usize as u64),
        "#22" => Some(native_shutdown_socket as *const () as usize as u64),
        "#5" => Some(native_getpeername as *const () as usize as u64),
        "#6" => Some(native_getsockname as *const () as usize as u64),
        "#21" => Some(native_setsockopt as *const () as usize as u64),
        "#57" => Some(native_wsa_get_host_name as *const () as usize as u64),
        "GetAddrInfoW" => Some(native_get_addr_info_w as *const () as usize as u64),
        "FreeAddrInfoW" => Some(native_free_addr_info_w as *const () as usize as u64),
        "#115" => Some(native_wsa_startup as *const () as usize as u64),
        "#116" => Some(native_wsa_cleanup as *const () as usize as u64),
        "#23" => Some(native_socket as *const () as usize as u64),
        "#3" => Some(native_close_socket as *const () as usize as u64),
        "#7" => Some(native_getsockopt as *const () as usize as u64),
        "WSAIoctl" => Some(native_wsa_ioctl as *const () as usize as u64),
        "WSARecv" => Some(native_wsa_recv as *const () as usize as u64),
        "WSASend" => Some(native_wsa_send as *const () as usize as u64),
        "#111" => Some(native_wsa_get_last_error as *const () as usize as u64),
        "#112" => Some(native_wsa_set_last_error as *const () as usize as u64),
        "GetSystemMetrics" => Some(native_get_system_metrics as *const () as usize as u64),
        "MessageBeep" => Some(native_message_beep as *const () as usize as u64),
        "CompareStringOrdinal" => Some(native_compare_string_ordinal as *const () as usize as u64),
        "GetLocaleInfoEx" => Some(native_get_locale_info_ex as *const () as usize as u64),
        "GetLocaleInfoW" => Some(native_get_locale_info_w as *const () as usize as u64),
        "GetUserPreferredUILanguages"
        | "GetSystemPreferredUILanguages"
        | "GetThreadPreferredUILanguages"
        | "GetProcessPreferredUILanguages" => {
            Some(native_get_preferred_ui_languages as *const () as usize as u64)
        }
        "GetUserDefaultUILanguage" | "GetSystemDefaultUILanguage" | "GetUserDefaultLangID"
        | "GetSystemDefaultLangID" => Some(native_get_default_ui_language as *const () as usize as u64),
        "LocaleNameToLCID" => Some(native_locale_name_to_lcid as *const () as usize as u64),
        "LCIDToLocaleName" => Some(native_lcid_to_locale_name as *const () as usize as u64),
        "IsValidLocaleName" => Some(native_is_valid_locale_name as *const () as usize as u64),
        "ResolveLocaleName" => Some(native_resolve_locale_name as *const () as usize as u64),
        "GetLongPathNameW" => Some(native_get_long_path_name_w as *const () as usize as u64),
        // WinFS has no short-name aliases, so the normalized DOS path is
        // the shortest spelling available for the path.
        "GetShortPathNameW" => Some(native_get_long_path_name_w as *const () as usize as u64),
        "ReadDirectoryChangesW" => {
            Some(native_read_directory_changes_w as *const () as usize as u64)
        }
        "AreFileApisANSI" => Some(native_are_file_apis_ansi as *const () as usize as u64),
        "LocalFree" => Some(native_local_free as *const () as usize as u64),
        "FreeLibraryAndExitThread" => {
            Some(native_free_library_and_exit_thread as *const () as usize as u64)
        }
        "GetNumberOfConsoleInputEvents" => {
            Some(native_get_number_of_console_input_events as *const () as usize as u64)
        }
        "SetNamedPipeHandleState" => {
            Some(native_set_named_pipe_handle_state as *const () as usize as u64)
        }
        "ConnectNamedPipe" => Some(native_connect_named_pipe as *const () as usize as u64),
        "WaitNamedPipeW" => Some(native_wait_named_pipe_w as *const () as usize as u64),
        "WaitNamedPipeA" => Some(native_wait_named_pipe_a as *const () as usize as u64),
        "CreateNamedPipeW" => Some(native_create_named_pipe_w as *const () as usize as u64),
        "CreateNamedPipeA" => Some(native_create_named_pipe_a as *const () as usize as u64),
        "CreateFileA" => Some(native_create_file_a as *const () as usize as u64),
        "GetTempPathA" => Some(native_get_temp_path_a as *const () as usize as u64),
        "GetTempPathW" | "GetTempPath2W" => Some(native_get_temp_path_w as *const () as usize as u64),
        "GetTempFileNameA" => Some(native_get_temp_file_name_a as *const () as usize as u64),
        "GetTempFileNameW" => Some(native_get_temp_file_name_w as *const () as usize as u64),
        "FindFirstFileA" => Some(native_find_first_file_a as *const () as usize as u64),
        "FindNextFileA" => Some(native_find_next_file_a as *const () as usize as u64),
        "FindFirstFileExA" => Some(native_find_first_file_ex_a as *const () as usize as u64),
        "CopyFileA" => Some(native_copy_file_a as *const () as usize as u64),
        "CopyFile2" => Some(native_copy_file2 as *const () as usize as u64),
        "CopyFileExW" => Some(native_copy_file_ex_w as *const () as usize as u64),
        "GetNamedPipeHandleStateW" => {
            Some(native_get_named_pipe_handle_state_w as *const () as usize as u64)
        }
        "GetNamedPipeHandleStateA" => {
            Some(native_get_named_pipe_handle_state_a as *const () as usize as u64)
        }
        "RegOpenKeyExW" => Some(native_reg_open_key_ex_w as *const () as usize as u64),
        "RegOpenKeyExA" => Some(native_reg_open_key_ex_a as *const () as usize as u64),
        "RegCreateKeyExW" => Some(native_reg_create_key_ex_w as *const () as usize as u64),
        "RegSetValueExW" => Some(native_reg_set_value_ex_w as *const () as usize as u64),
        "RegQueryValueExW" => Some(native_reg_query_value_ex_w as *const () as usize as u64),
        "RegCloseKey" => Some(native_reg_close_key as *const () as usize as u64),
        "RegGetValueW" => Some(native_reg_get_value_w as *const () as usize as u64),
        // Private entry point of the seeded cmd.exe.
        "WinrunCmdMain" => Some(native_winrun_cmd_main as *const () as usize as u64),
        "RegDeleteValueW" => Some(native_reg_delete_value_w as *const () as usize as u64),
        "RegDeleteKeyW" => Some(native_reg_delete_key_w as *const () as usize as u64),
        "RegDeleteTreeW" => Some(native_reg_delete_tree_w as *const () as usize as u64),
        "RegEnumKeyExW" => Some(native_reg_enum_key_ex_w as *const () as usize as u64),
        "RegEnumValueW" => Some(native_reg_enum_value_w as *const () as usize as u64),
        "RegQueryInfoKeyW" => Some(native_reg_query_info_key_w as *const () as usize as u64),
        "CreateFileMappingW" => Some(native_create_file_mapping_w as *const () as usize as u64),
        "CreateFileMappingA" => Some(native_create_file_mapping_a as *const () as usize as u64),
        "MapViewOfFile" => Some(native_map_view_of_file as *const () as usize as u64),
        "MapViewOfFileEx" => Some(native_map_view_of_file_ex as *const () as usize as u64),
        "FlushViewOfFile" => Some(native_flush_view_of_file as *const () as usize as u64),
        "UnmapViewOfFile" => Some(native_unmap_view_of_file as *const () as usize as u64),
        "CryptAcquireContextW" => Some(native_crypt_acquire_context_w as *const () as usize as u64),
        "CryptGenRandom" => Some(native_crypt_gen_random as *const () as usize as u64),
        "CryptReleaseContext" => Some(native_crypt_release_context as *const () as usize as u64),
        "SystemFunction036" => Some(native_rtl_gen_random as *const () as usize as u64),
        "EventRegister" => Some(native_event_register as *const () as usize as u64),
        "EventUnregister" => Some(native_event_unregister as *const () as usize as u64),
        "EventSetInformation" => Some(native_event_set_information as *const () as usize as u64),
        "EventWriteTransfer" => Some(native_event_write_transfer as *const () as usize as u64),
        "SetConsoleCtrlHandler" => {
            Some(native_set_console_ctrl_handler as *const () as usize as u64)
        }
        "CreateSemaphoreA" => Some(native_create_semaphore_a as *const () as usize as u64),
        "ReleaseSemaphore" => Some(native_release_semaphore as *const () as usize as u64),
        "CreateJobObjectW" => Some(native_create_job_object_w as *const () as usize as u64),
        "CreateJobObjectA" => Some(native_create_job_object_a as *const () as usize as u64),
        "SetInformationJobObject" => {
            Some(native_set_information_job_object as *const () as usize as u64)
        }
        "AssignProcessToJobObject" => {
            Some(native_assign_process_to_job_object as *const () as usize as u64)
        }
        "TerminateJobObject" => Some(native_terminate_job_object as *const () as usize as u64),
        "RegisterWaitForSingleObject" => {
            Some(native_register_wait_for_single_object as *const () as usize as u64)
        }
        "UnregisterWaitEx" => Some(native_unregister_wait_ex as *const () as usize as u64),
        "UnregisterWait" => Some(native_unregister_wait_ex as *const () as usize as u64),
        "_get_osfhandle" => Some(native_crt_get_osfhandle as *const () as usize as u64),
        "_open_osfhandle" => Some(native_crt_open_osfhandle as *const () as usize as u64),
        "_close" | "close" => Some(native_crt_close as *const () as usize as u64),
        "_read" | "read" => Some(native_crt_read as *const () as usize as u64),
        "_write" | "write" => Some(native_crt_write as *const () as usize as u64),
        "_isatty" | "isatty" => Some(native_crt_isatty as *const () as usize as u64),
        "CreateIoCompletionPort" => {
            Some(native_create_io_completion_port as *const () as usize as u64)
        }
        "SetFileCompletionNotificationModes" => {
            Some(native_set_file_completion_notification_modes as *const () as usize as u64)
        }
        "PostQueuedCompletionStatus" => {
            Some(native_post_queued_completion_status as *const () as usize as u64)
        }
        "GetQueuedCompletionStatusEx" => {
            Some(native_get_queued_completion_status_ex as *const () as usize as u64)
        }
        "GetQueuedCompletionStatus" => {
            Some(native_get_queued_completion_status as *const () as usize as u64)
        }
        "GetOverlappedResult" => Some(native_get_overlapped_result as *const () as usize as u64),
        "CancelIoEx" => Some(native_cancel_io_ex as *const () as usize as u64),
        "CancelIo" => Some(native_cancel_io as *const () as usize as u64),
        "VerSetConditionMask" => Some(native_ver_set_condition_mask as *const () as usize as u64),
        "VerifyVersionInfoW" => Some(native_verify_version_info_w as *const () as usize as u64),
        "GetCommandLineW" => Some(native_get_command_line_w as *const () as usize as u64),
        "GetCommandLineA" => Some(native_get_command_line_a as *const () as usize as u64),
        "GetLastError" => Some(native_get_last_error as *const () as usize as u64),
        "SetLastError" => Some(native_set_last_error as *const () as usize as u64),
        "SetErrorMode" => Some(native_set_error_mode as *const () as usize as u64),
        "GetStartupInfoW" => Some(native_get_startup_info_w as *const () as usize as u64),
        "GetStartupInfoA" => Some(native_get_startup_info_a as *const () as usize as u64),
        "GetVersion" => Some(native_get_version as *const () as usize as u64),
        "GetSystemDirectoryW" => Some(native_get_system_directory_w as *const () as usize as u64),
        "lstrlenW" => Some(native_lstrlen_w as *const () as usize as u64),
        "lstrcpyW" => Some(native_lstrcpy_w as *const () as usize as u64),
        "lstrcatW" => Some(native_lstrcat_w as *const () as usize as u64),
        "SetDefaultDllDirectories" => {
            Some(native_set_default_dll_directories as *const () as usize as u64)
        }
        "SetFileApisToOEM" => Some(native_set_file_apis_to_oem as *const () as usize as u64),
        "CoInitialize" => Some(native_co_initialize as *const () as usize as u64),
        "LookupPrivilegeValueW" => {
            Some(native_lookup_privilege_value_w as *const () as usize as u64)
        }
        "AdjustTokenPrivileges" => {
            Some(native_adjust_token_privileges as *const () as usize as u64)
        }
        "SHGetFolderPathW" => Some(native_sh_get_folder_path_w as *const () as usize as u64),
        "GetProcessHeap" => Some(native_get_process_heap as *const () as usize as u64),
        "GetCurrentThreadId" => Some(native_get_current_thread_id as *const () as usize as u64),
        "GetCurrentProcessId" => Some(native_get_current_process_id as *const () as usize as u64),
        "GetCurrentProcess" => Some(native_get_current_process as *const () as usize as u64),
        "OpenProcessToken" => Some(native_open_process_token as *const () as usize as u64),
        "GetUserNameW" => Some(native_get_user_name_w as *const () as usize as u64),
        "GetExitCodeProcess" => Some(native_get_exit_code_process as *const () as usize as u64),
        "TerminateProcess" => Some(native_terminate_process as *const () as usize as u64),
        "GetCurrentThread" => Some(native_get_current_thread as *const () as usize as u64),
        "GetModuleHandleA" => Some(native_get_module_handle_a as *const () as usize as u64),
        "VirtualProtect" => Some(native_virtual_protect as *const () as usize as u64),
        "VirtualAlloc" => Some(native_virtual_alloc as *const () as usize as u64),
        "VirtualFree" => Some(native_virtual_free as *const () as usize as u64),
        "VirtualQuery" => Some(native_virtual_query as *const () as usize as u64),
        "LoadLibraryExW" => Some(native_load_library_ex_w as *const () as usize as u64),
        "LoadLibraryW" => Some(native_load_library_w as *const () as usize as u64),
        "LoadLibraryA" => Some(native_load_library_a as *const () as usize as u64),
        "IsWow64Process" => Some(native_is_wow64_process as *const () as usize as u64),
        "IsWow64Process2" => Some(native_is_wow64_process2 as *const () as usize as u64),
        "GetWindowsDirectoryW" | "GetSystemWindowsDirectoryW" => {
            Some(native_get_windows_directory_w as *const () as usize as u64)
        }
        "GetWindowsDirectoryA" | "GetSystemWindowsDirectoryA" => {
            Some(native_get_windows_directory_a as *const () as usize as u64)
        }
        "IsDebuggerPresent" => Some(native_is_debugger_present as *const () as usize as u64),
        "OutputDebugStringW" | "OutputDebugStringA" => {
            Some(native_output_debug_string as *const () as usize as u64)
        }
        "LoadLibraryExA" => Some(native_load_library_ex_a as *const () as usize as u64),
        "GetProcAddress" => Some(native_get_proc_address as *const () as usize as u64),
        "FreeLibrary" => Some(native_free_library as *const () as usize as u64),
        "QueryPerformanceCounter" => {
            Some(native_query_performance_counter as *const () as usize as u64)
        }
        "QueryPerformanceFrequency" => {
            Some(native_query_performance_frequency as *const () as usize as u64)
        }
        "GetTickCount" => Some(native_get_tick_count as *const () as usize as u64),
        "GetTickCount64" => Some(native_get_tick_count64 as *const () as usize as u64),
        "Sleep" => Some(native_sleep as *const () as usize as u64),
        "SwitchToThread" => Some(native_switch_to_thread as *const () as usize as u64),
        "GetTimeZoneInformation" => {
            Some(native_get_time_zone_information as *const () as usize as u64)
        }
        "GetDynamicTimeZoneInformation" => {
            Some(native_get_dynamic_time_zone_information as *const () as usize as u64)
        }
        "timeGetTime" => Some(native_time_get_time as *const () as usize as u64),
        "GlobalMemoryStatusEx" => Some(native_global_memory_status_ex as *const () as usize as u64),
        "InitializeCriticalSectionEx" => {
            Some(native_initialize_critical_section_ex as *const () as usize as u64)
        }
        "InitializeCriticalSectionAndSpinCount" => {
            Some(native_initialize_critical_section_and_spin_count as *const () as usize as u64)
        }
        "InitializeCriticalSection" => {
            Some(native_initialize_critical_section as *const () as usize as u64)
        }
        "InitializeSRWLock" => Some(native_initialize_srw_lock as *const () as usize as u64),
        "AcquireSRWLockExclusive" => {
            Some(native_acquire_srw_lock_exclusive as *const () as usize as u64)
        }
        "AcquireSRWLockShared" => Some(native_acquire_srw_lock_shared as *const () as usize as u64),
        "TryAcquireSRWLockExclusive" => {
            Some(native_try_acquire_srw_lock_exclusive as *const () as usize as u64)
        }
        "TryAcquireSRWLockShared" => {
            Some(native_try_acquire_srw_lock_shared as *const () as usize as u64)
        }
        "ReleaseSRWLockExclusive" => {
            Some(native_release_srw_lock_exclusive as *const () as usize as u64)
        }
        "ReleaseSRWLockShared" => Some(native_release_srw_lock_shared as *const () as usize as u64),
        "InitializeConditionVariable" => {
            Some(native_initialize_condition_variable as *const () as usize as u64)
        }
        "WakeConditionVariable" => {
            Some(native_wake_condition_variable as *const () as usize as u64)
        }
        "WakeAllConditionVariable" => {
            Some(native_wake_all_condition_variable as *const () as usize as u64)
        }
        "SleepConditionVariableSRW" => {
            Some(native_sleep_condition_variable_srw as *const () as usize as u64)
        }
        "SleepConditionVariableCS" => {
            Some(native_sleep_condition_variable_cs as *const () as usize as u64)
        }
        "InitOnceInitialize" => Some(native_init_once_initialize as *const () as usize as u64),
        "InitOnceExecuteOnce" => Some(native_init_once_execute_once as *const () as usize as u64),
        "InitOnceBeginInitialize" => {
            Some(native_init_once_begin_initialize as *const () as usize as u64)
        }
        "InitOnceComplete" => Some(native_init_once_complete as *const () as usize as u64),
        "TlsAlloc" => Some(native_tls_alloc as *const () as usize as u64),
        "TlsFree" => Some(native_tls_free as *const () as usize as u64),
        "TlsGetValue" => Some(native_tls_get_value as *const () as usize as u64),
        "TlsSetValue" => Some(native_tls_set_value as *const () as usize as u64),
        "EncodePointer" => Some(native_encode_pointer as *const () as usize as u64),
        "DecodePointer" => Some(native_decode_pointer as *const () as usize as u64),
        "IsProcessorFeaturePresent" => {
            Some(native_is_processor_feature_present as *const () as usize as u64)
        }
        "RtlGetVersion" => Some(native_rtl_get_version as *const () as usize as u64),
        "NtReadFile" => Some(native_nt_read_file as *const () as usize as u64),
        "NtWriteFile" => Some(native_nt_write_file as *const () as usize as u64),
        "RtlNtStatusToDosError" => {
            Some(native_rtl_nt_status_to_dos_error as *const () as usize as u64)
        }
        "EnterCriticalSection" => Some(native_enter_critical_section as *const () as usize as u64),
        "LeaveCriticalSection" => Some(native_leave_critical_section as *const () as usize as u64),
        "DeleteCriticalSection" => {
            Some(native_delete_critical_section as *const () as usize as u64)
        }
        "InitializeSListHead" => Some(native_initialize_slist_head as *const () as usize as u64),
        "InterlockedPushEntrySList" => {
            Some(native_interlocked_push_entry_slist as *const () as usize as u64)
        }
        "InterlockedPopEntrySList" => {
            Some(native_interlocked_pop_entry_slist as *const () as usize as u64)
        }
        "InterlockedFlushSList" => {
            Some(native_interlocked_flush_slist as *const () as usize as u64)
        }
        "QueryDepthSList" => Some(native_query_depth_slist as *const () as usize as u64),
        "FlsAlloc" => Some(native_fls_alloc as *const () as usize as u64),
        "FlsFree" => Some(native_fls_free as *const () as usize as u64),
        "FlsGetValue" => Some(native_fls_get_value as *const () as usize as u64),
        "FlsSetValue" => Some(native_fls_set_value as *const () as usize as u64),
        "GetSystemTimeAsFileTime" | "GetSystemTimePreciseAsFileTime" => {
            Some(native_get_system_time_as_file_time as *const () as usize as u64)
        }
        "GetSystemTime" => Some(native_get_system_time as *const () as usize as u64),
        "SystemTimeToFileTime" => {
            Some(native_system_time_to_file_time as *const () as usize as u64)
        }
        "GetSystemInfo" => Some(native_get_system_info as *const () as usize as u64),
        "GetProcessAffinityMask" => {
            Some(native_get_process_affinity_mask as *const () as usize as u64)
        }
        "GetNativeSystemInfo" => Some(native_get_native_system_info as *const () as usize as u64),
        "GetFullPathNameW" => Some(native_get_full_path_name_w as *const () as usize as u64),
        "FormatMessageW" => Some(native_format_message_w as *const () as usize as u64),
        "FormatMessageA" => Some(native_format_message_a as *const () as usize as u64),
        "GetUserProfileDirectoryW" => {
            Some(native_get_user_profile_directory_w as *const () as usize as u64)
        }
        "GetStdHandle" => Some(native_get_std_handle as *const () as usize as u64),
        "SetStdHandle" => Some(native_set_std_handle as *const () as usize as u64),
        "SetHandleInformation" => Some(native_set_handle_information as *const () as usize as u64),
        "DuplicateHandle" => Some(native_duplicate_handle as *const () as usize as u64),
        "GetFileType" => Some(native_get_file_type as *const () as usize as u64),
        "GetModuleFileNameW" => Some(native_get_module_file_name_w as *const () as usize as u64),
        "GetModuleHandleW" => Some(native_get_module_handle_w as *const () as usize as u64),
        "GetModuleHandleExW" => Some(native_get_module_handle_ex_w as *const () as usize as u64),
        "GetEnvironmentStringsW" => {
            Some(native_get_environment_strings_w as *const () as usize as u64)
        }
        "FreeEnvironmentStringsW" => {
            Some(native_free_environment_strings_w as *const () as usize as u64)
        }
        "SetUnhandledExceptionFilter" => {
            Some(native_set_unhandled_exception_filter as *const () as usize as u64)
        }
        "AddVectoredExceptionHandler" => {
            Some(native_add_vectored_exception_handler as *const () as usize as u64)
        }
        "RemoveVectoredExceptionHandler" => {
            Some(native_remove_vectored_exception_handler as *const () as usize as u64)
        }
        "SetThreadStackGuarantee" => {
            Some(native_set_thread_stack_guarantee as *const () as usize as u64)
        }
        "GetACP" => Some(native_get_acp as *const () as usize as u64),
        "GetOEMCP" => Some(native_get_oem_cp as *const () as usize as u64),
        "IsValidCodePage" => Some(native_is_valid_code_page as *const () as usize as u64),
        "GetCPInfo" => Some(native_get_cp_info as *const () as usize as u64),
        "MultiByteToWideChar" => Some(native_multi_byte_to_wide_char as *const () as usize as u64),
        "GetStringTypeW" => Some(native_get_string_type_w as *const () as usize as u64),
        "LCMapStringW" => Some(native_lc_map_string_w as *const () as usize as u64),
        "WideCharToMultiByte" => Some(native_wide_char_to_multi_byte as *const () as usize as u64),
        "HeapAlloc" => Some(native_heap_alloc as *const () as usize as u64),
        "HeapReAlloc" => Some(native_heap_realloc as *const () as usize as u64),
        "HeapSize" => Some(native_heap_size as *const () as usize as u64),
        "HeapFree" => Some(native_heap_free as *const () as usize as u64),
        "ProcessPrng" => Some(native_process_prng as *const () as usize as u64),
        "GetConsoleMode" => Some(native_get_console_mode as *const () as usize as u64),
        "GetConsoleOutputCP" => Some(native_get_console_output_cp as *const () as usize as u64),
        "GetConsoleCursorInfo" => Some(native_get_console_cursor_info as *const () as usize as u64),
        "SetConsoleCursorInfo" => Some(native_set_console_cursor_info as *const () as usize as u64),
        "SetConsoleCursorPosition" => {
            Some(native_set_console_cursor_position as *const () as usize as u64)
        }
        "GetConsoleScreenBufferInfo" => {
            Some(native_get_console_screen_buffer_info as *const () as usize as u64)
        }
        "SetConsoleScreenBufferSize" => {
            Some(native_set_console_screen_buffer_size as *const () as usize as u64)
        }
        "SetConsoleWindowInfo" => Some(native_set_console_window_info as *const () as usize as u64),
        "SetConsoleActiveScreenBuffer" => {
            Some(native_set_console_active_screen_buffer as *const () as usize as u64)
        }
        "SetConsoleMode" => Some(native_set_console_mode as *const () as usize as u64),
        "SetConsoleTitleW" => Some(native_set_console_title_w as *const () as usize as u64),
        "GetLogicalProcessorInformation" => {
            Some(native_get_logical_processor_information as *const () as usize as u64)
        }
        "GetAdaptersAddresses" => Some(native_get_adapters_addresses as *const () as usize as u64),
        "GetEnvironmentVariableW" => {
            Some(native_get_environment_variable_w as *const () as usize as u64)
        }
        "GetEnvironmentVariableA" => {
            Some(native_get_environment_variable_a as *const () as usize as u64)
        }
        "SetEnvironmentVariableW" => {
            Some(native_set_environment_variable_w as *const () as usize as u64)
        }
        "NeedCurrentDirectoryForExePathW" => {
            Some(native_need_current_directory_for_exe_path_w as *const () as usize as u64)
        }
        "GetCurrentDirectoryW" => Some(native_get_current_directory_w as *const () as usize as u64),
        "GetComputerNameExW" => Some(native_get_computer_name_ex_w as *const () as usize as u64),
        "SetFileTime" => Some(native_set_file_time as *const () as usize as u64),
        "SetFilePointerEx" => Some(native_set_file_pointer_ex as *const () as usize as u64),
        "SetFilePointer" => Some(native_set_file_pointer as *const () as usize as u64),
        "WriteFile" => Some(native_write_file as *const () as usize as u64),
        "WriteConsoleW" => Some(native_write_console_w as *const () as usize as u64),
        "WriteConsoleOutputA" => Some(native_write_console_output_a as *const () as usize as u64),
        "ExitProcess" => Some(native_exit_process as *const () as usize as u64),
        "CreateProcessW" => Some(native_create_process_w as *const () as usize as u64),
        "CreateFileW" => Some(native_create_file_w as *const () as usize as u64),
        "CreateFile2" => Some(native_create_file2 as *const () as usize as u64),
        "OpenFileById" => Some(native_open_file_by_id as *const () as usize as u64),
        "SetFileValidData" => Some(native_set_file_valid_data as *const () as usize as u64),
        "WriteFileGather" => Some(native_write_file_gather as *const () as usize as u64),
        "LockFile" => Some(native_lock_file as *const () as usize as u64),
        "UnlockFile" => Some(native_unlock_file as *const () as usize as u64),
        "FindFirstStreamW" => Some(native_find_first_stream_w as *const () as usize as u64),
        "GetFileAttributesW" => Some(native_get_file_attributes_w as *const () as usize as u64),
        "SetFileAttributesW" => Some(native_set_file_attributes_w as *const () as usize as u64),
        "SetFileAttributesA" => Some(native_set_file_attributes_a as *const () as usize as u64),
        "CreateHardLinkA" => Some(native_create_hard_link_a as *const () as usize as u64),
        "CreateHardLinkW" => Some(native_create_hard_link_w as *const () as usize as u64),
        "CreateSymbolicLinkA" => Some(native_create_symbolic_link_a as *const () as usize as u64),
        "CreateSymbolicLinkW" => Some(native_create_symbolic_link_w as *const () as usize as u64),
        "ReplaceFileA" => Some(native_replace_file_a as *const () as usize as u64),
        "ReplaceFileW" => Some(native_replace_file_w as *const () as usize as u64),
        "GetFileAttributesExW" => {
            Some(native_get_file_attributes_ex_w as *const () as usize as u64)
        }
        "GetFileInformationByHandle" => {
            Some(native_get_file_information_by_handle as *const () as usize as u64)
        }
        "GetFileInformationByHandleEx" => {
            Some(native_get_file_information_by_handle_ex as *const () as usize as u64)
        }
        "GetFileSizeEx" => Some(native_get_file_size_ex as *const () as usize as u64),
        "GetOverlappedResultEx" => {
            Some(native_get_overlapped_result_ex as *const () as usize as u64)
        }
        "SetFileInformationByHandle" => {
            Some(native_set_file_information_by_handle as *const () as usize as u64)
        }
        "GetFinalPathNameByHandleW" => {
            Some(native_get_final_path_name_by_handle_w as *const () as usize as u64)
        }
        "GetFinalPathNameByHandleA" => {
            Some(native_get_final_path_name_by_handle_a as *const () as usize as u64)
        }
        "FindFirstFileExW" => Some(native_find_first_file_ex_w as *const () as usize as u64),
        "FindFirstFileW" => Some(native_find_first_file_w as *const () as usize as u64),
        "FindNextFileW" => Some(native_find_next_file_w as *const () as usize as u64),
        "FindClose" => Some(native_find_close as *const () as usize as u64),
        "CreateThread" => Some(native_create_thread as *const () as usize as u64),
        "ResumeThread" => Some(native_resume_thread as *const () as usize as u64),
        "WaitForSingleObject" => Some(native_wait_for_single_object as *const () as usize as u64),
        "CreateEventW" => Some(native_create_event_w as *const () as usize as u64),
        "CreateEventA" => Some(native_create_event_a as *const () as usize as u64),
        "CreateEventExW" => Some(native_create_event_ex_w as *const () as usize as u64),
        "CreateEventExA" => Some(native_create_event_ex_a as *const () as usize as u64),
        "SetEvent" => Some(native_set_event as *const () as usize as u64),
        "ResetEvent" => Some(native_reset_event as *const () as usize as u64),
        "WaitOnAddress" => Some(native_wait_on_address as *const () as usize as u64),
        "WakeByAddressAll" => Some(native_wake_by_address_all as *const () as usize as u64),
        "WakeByAddressSingle" => Some(native_wake_by_address_single as *const () as usize as u64),
        "CreateWaitableTimerExW" => {
            Some(native_create_waitable_timer_ex_w as *const () as usize as u64)
        }
        "SetWaitableTimer" => Some(native_set_waitable_timer as *const () as usize as u64),
        "ReadFile" => Some(native_read_file as *const () as usize as u64),
        "CloseHandle" => Some(native_close_handle as *const () as usize as u64),
        "CreateDirectoryW" => Some(native_create_directory_w as *const () as usize as u64),
        "RemoveDirectoryA" => Some(native_remove_directory_a as *const () as usize as u64),
        "RemoveDirectoryW" => Some(native_remove_directory_w as *const () as usize as u64),
        "DeleteFileW" => Some(native_delete_file_w as *const () as usize as u64),
        "DeleteFileA" => Some(native_delete_file_a as *const () as usize as u64),
        "MoveFileW" => Some(native_move_file_w as *const () as usize as u64),
        "MoveFileA" => Some(native_move_file_a as *const () as usize as u64),
        "MoveFileExW" => Some(native_move_file_ex_w as *const () as usize as u64),
        "CopyFileW" => Some(native_copy_file_w as *const () as usize as u64),
        "FlushFileBuffers" => Some(native_flush_file_buffers as *const () as usize as u64),
        "SetEndOfFile" => Some(native_set_end_of_file as *const () as usize as u64),
        "ReOpenFile" => Some(native_reopen_file as *const () as usize as u64),
        _ => None,
    }
}

pub(super) extern "win64" fn native_local_free(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    let Some(process) = process_ctx() else {
        return value;
    };
    if process
        .heap_allocations
        .lock()
        .is_ok_and(|mut values| values.remove(&value).is_some())
    {
        unsafe { free(value as *mut c_void) };
        0
    } else {
        native_set_last_error(6);
        value
    }
}

pub(super) struct MissingImportStubs {
    pub(super) _code: Mapping,
    pub(super) _messages: Vec<Vec<u8>>,
}

extern "win64" fn native_missing_import(message: *const u8, len: u64) -> ! {
    let mut offset = 0;
    while offset < len as usize {
        let written = unsafe { write(2, message.add(offset).cast(), len as usize - offset) };
        if written <= 0 {
            break;
        }
        offset += written as usize;
    }
    if std::env::var_os("WINRUN_NATIVE_WORKER").as_deref() == Some(std::ffi::OsStr::new("1")) {
        let fd = NATIVE_WORKER_RESULT_FD.load(Ordering::Acquire);
        if fd >= 0 {
            let code = 126u32.to_le_bytes();
            unsafe { write(fd, code.as_ptr().cast(), code.len()) };
        }
    }
    unsafe { _exit(126) }
}

pub(super) fn patch_baseline_imports(
    mapping: &Mapping,
    img: &PeImage,
    strict_imports: bool,
) -> Result<Option<MissingImportStubs>, String> {
    let imports: Vec<_> = img.imports.iter().chain(&img.unsupported).collect();
    let missing = imports
        .iter()
        .filter(|import| !supports_import(&import.dll, &import.func))
        .count();
    if missing > 0 && strict_imports {
        let import = imports
            .iter()
            .find(|import| !supports_import(&import.dll, &import.func))
            .unwrap();
        return Err(format!(
            "unsupported native import: {}!{}",
            import.dll, import.func
        ));
    }
    let mut stubs = if missing == 0 {
        None
    } else {
        let size = page_len(
            missing
                .checked_mul(32)
                .ok_or("too many native import stubs")?,
        )?;
        let ptr = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == MAP_FAILED {
            return Err(format!(
                "native import stub allocation failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Some(MissingImportStubs {
            _code: Mapping {
                ptr: ptr.cast(),
                len: size,
            },
            _messages: Vec::with_capacity(missing),
        })
    };
    let mut stub_index = 0;
    for import in imports {
        let value = if supports_import(&import.dll, &import.func) {
            let name = ordinal_export_name(&import.dll, &import.func).unwrap_or(&import.func);
            baseline_trampoline(name).unwrap()
        } else {
            let stubs = stubs.as_mut().unwrap();
            let message = format!(
                "unsupported native import called: {}!{}\n",
                import.dll, import.func
            )
            .into_bytes();
            let message_ptr = message.as_ptr() as u64;
            let message_len = message.len() as u64;
            stubs._messages.push(message);
            let code =
                unsafe { std::slice::from_raw_parts_mut(stubs._code.ptr.add(stub_index * 32), 32) };
            code[0..2].copy_from_slice(&[0x48, 0xB9]); // mov rcx, message
            code[2..10].copy_from_slice(&message_ptr.to_le_bytes());
            code[10..12].copy_from_slice(&[0x48, 0xBA]); // mov rdx, length
            code[12..20].copy_from_slice(&message_len.to_le_bytes());
            code[20..22].copy_from_slice(&[0x48, 0xB8]); // mov rax, handler
            code[22..30].copy_from_slice(
                &(native_missing_import as *const () as usize as u64).to_le_bytes(),
            );
            code[30..32].copy_from_slice(&[0xFF, 0xE0]); // jmp rax
            stub_index += 1;
            code.as_ptr() as u64
        };
        let off = import.iat_rva as usize;
        if off.checked_add(8).is_none_or(|end| end > mapping.len) {
            return Err(format!(
                "native IAT slot out of range: {}!{}",
                import.dll, import.func
            ));
        }
        // SAFETY: the mapping is still RW and the checked IAT slot is in it.
        unsafe { (mapping.ptr.add(off) as *mut u64).write_unaligned(value) };
    }
    if let Some(stubs) = &stubs {
        if unsafe {
            mprotect(
                stubs._code.ptr.cast(),
                stubs._code.len,
                PROT_READ | PROT_EXEC,
            )
        } != 0
        {
            return Err(format!(
                "native import stubs could not be made executable: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(stubs)
}
