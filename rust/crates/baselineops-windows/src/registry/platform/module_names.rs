use super::{
    ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, OwnedKey,
    PCWSTR, PlatformError, RegEnumValueW, RegOpenKeyExW, RegistryLocation, RegistryRead,
    RegistryValue, RegistryValueName, check_status, location_path, query_value, wide,
};

pub(crate) fn list_hklm_module_names()
-> Result<crate::powershell_logging::ModuleNamesRead, PlatformError> {
    unsafe {
        let path = wide(location_path(RegistryLocation::PowerShellModuleNames));
        let mut raw_key = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            KEY_READ,
            &raw mut raw_key,
        );
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(crate::powershell_logging::ModuleNamesRead::missing());
        }
        check_status(status)?;
        let key = OwnedKey(raw_key);
        let mut values = std::collections::BTreeMap::new();
        for index in 0..=u32::from(crate::powershell_logging::MAX_MODULE_NAMES) {
            let Some((numeric, value)) = module_name_record(&key, index)? else {
                break;
            };
            values.insert(numeric, value);
        }
        Ok(crate::powershell_logging::ModuleNamesRead {
            values,
            complete: true,
        })
    }
}

unsafe fn module_name_record(
    key: &OwnedKey,
    index: u32,
) -> Result<Option<(u16, String)>, PlatformError> {
    let mut name = vec![0_u16; 4];
    let mut name_len = u32::try_from(name.len())
        .map_err(|_| PlatformError::TrustFailure("module name length overflow".into()))?;
    let mut value_type = 0_u32;
    let mut size = 0_u32;
    let status = RegEnumValueW(
        key.0,
        index,
        Some(windows::core::PWSTR(name.as_mut_ptr())),
        &raw mut name_len,
        None,
        Some(&raw mut value_type),
        None,
        Some(&raw mut size),
    );
    if status == ERROR_NO_MORE_ITEMS {
        return Ok(None);
    }
    check_status(status)?;
    let numeric = module_name_index(&name, name_len)?;
    let RegistryRead::Present(RegistryValue::String(value)) =
        query_value(key, RegistryValueName::ModuleName(numeric))?
    else {
        return Err(PlatformError::TrustFailure(
            "ModuleNames value has an unexpected type".into(),
        ));
    };
    Ok(Some((numeric, value)))
}

fn module_name_index(name: &[u16], length: u32) -> Result<u16, PlatformError> {
    String::from_utf16(
        &name[..usize::try_from(length)
            .map_err(|_| PlatformError::TrustFailure("module name length overflow".into()))?],
    )
    .map_err(|error| PlatformError::TrustFailure(error.to_string()))?
    .parse::<u16>()
    .ok()
    .filter(|value| (1..=crate::powershell_logging::MAX_MODULE_NAMES).contains(value))
    .ok_or_else(|| {
        PlatformError::TrustFailure("ModuleNames has a non-numbered or out-of-range value".into())
    })
}
