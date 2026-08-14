//! Shell-free, bounded IP Helper network inventory for capability 29.

use crate::PlatformError;
use baselineops_capabilities::NetworkInventoryObservation;

/// Collect network interfaces using `GetAdaptersAddresses` without invoking a shell.
///
/// # Errors
///
/// Returns [`PlatformError::UnsupportedPlatform`] outside Windows and a typed
/// operating-system error when IP Helper cannot produce an inventory.
pub fn audit_network_inventory() -> Result<NetworkInventoryObservation, PlatformError> {
    platform::audit_network_inventory()
}

#[cfg(not(windows))]
mod platform {
    use super::{NetworkInventoryObservation, PlatformError};

    pub(super) fn audit_network_inventory() -> Result<NetworkInventoryObservation, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

    use super::{NetworkInventoryObservation, PlatformError};
    use baselineops_capabilities::{NetworkInterfaceObservation, Observation};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, WIN32_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_DNS_SERVER_ADDRESS_XP, IP_ADAPTER_GATEWAY_ADDRESS_LH,
        IP_ADAPTER_UNICAST_ADDRESS_LH,
    };
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
    };

    const MAX_BUFFER_BYTES: usize = 4 * 1024 * 1024;
    const MAX_INTERFACES: usize = 256;
    const MAX_ADDRESSES_PER_INTERFACE: usize = 128;

    pub(super) fn audit_network_inventory() -> Result<NetworkInventoryObservation, PlatformError> {
        unsafe {
            let mut bytes = 0_u32;
            let status = GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                GAA_FLAG_INCLUDE_GATEWAYS,
                None,
                None,
                &raw mut bytes,
            );
            if status != ERROR_BUFFER_OVERFLOW.0 || bytes == 0 || bytes as usize > MAX_BUFFER_BYTES
            {
                return Err(PlatformError::TrustFailure(
                    "IP Helper returned an invalid adapter buffer size".into(),
                ));
            }
            let word_count = (bytes as usize).div_ceil(size_of::<usize>());
            let mut buffer = vec![0_usize; word_count];
            let status = GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                GAA_FLAG_INCLUDE_GATEWAYS,
                None,
                Some(buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &raw mut bytes,
            );
            if status != WIN32_ERROR(0).0 {
                return Err(PlatformError::TrustFailure(format!(
                    "GetAdaptersAddresses failed with {status}"
                )));
            }
            let mut records = Vec::new();
            let mut adapter = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            while !adapter.is_null() && records.len() < MAX_INTERFACES {
                records.push(Observation::Present(read_adapter(&*adapter)));
                adapter = (*adapter).Next;
            }
            Ok(NetworkInventoryObservation {
                interfaces: records,
                enumeration_complete: adapter.is_null(),
            })
        }
    }

    unsafe fn read_adapter(adapter: &IP_ADAPTER_ADDRESSES_LH) -> NetworkInterfaceObservation {
        let interface_index = adapter.Anonymous1.Anonymous.IfIndex;
        let (ipv4_addresses, ipv6_addresses) = unicast_addresses(adapter.FirstUnicastAddress);
        let (ipv4_gateways, ipv6_gateways) = gateways(adapter.FirstGatewayAddress);
        let (dns_servers, _) = dns_servers(adapter.FirstDnsServerAddress);
        NetworkInterfaceObservation {
            interface_index,
            interface_alias: wide_string(adapter.FriendlyName.0),
            ipv4_addresses,
            ipv6_addresses,
            ipv4_gateways,
            ipv6_gateways,
            dns_servers,
        }
    }

    unsafe fn unicast_addresses(
        mut address: *mut IP_ADAPTER_UNICAST_ADDRESS_LH,
    ) -> (Vec<String>, Vec<String>) {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for _ in 0..MAX_ADDRESSES_PER_INTERFACE {
            if address.is_null() {
                break;
            }
            if let Some((family, value)) = socket_text(&(*address).Address) {
                if family == AF_INET {
                    ipv4.push(value);
                } else if family == AF_INET6 {
                    ipv6.push(value);
                }
            }
            address = (*address).Next;
        }
        (ipv4, ipv6)
    }

    unsafe fn gateways(
        mut address: *mut IP_ADAPTER_GATEWAY_ADDRESS_LH,
    ) -> (Vec<String>, Vec<String>) {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for _ in 0..MAX_ADDRESSES_PER_INTERFACE {
            if address.is_null() {
                break;
            }
            if let Some((family, value)) = socket_text(&(*address).Address) {
                if family == AF_INET {
                    ipv4.push(value);
                } else if family == AF_INET6 {
                    ipv6.push(value);
                }
            }
            address = (*address).Next;
        }
        (ipv4, ipv6)
    }

    unsafe fn dns_servers(
        mut address: *mut IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
    ) -> (Vec<String>, bool) {
        let mut servers = Vec::new();
        for _ in 0..MAX_ADDRESSES_PER_INTERFACE {
            if address.is_null() {
                return (servers, true);
            }
            if let Some((_, value)) = socket_text(&(*address).Address) {
                servers.push(value);
            }
            address = (*address).Next;
        }
        (servers, address.is_null())
    }

    unsafe fn socket_text(
        address: &SOCKET_ADDRESS,
    ) -> Option<(windows::Win32::Networking::WinSock::ADDRESS_FAMILY, String)> {
        if address.lpSockaddr.is_null() {
            return None;
        }
        let family = (*address.lpSockaddr).sa_family;
        if family == AF_INET
            && address.iSockaddrLength >= i32::try_from(size_of::<SOCKADDR_IN>()).ok()?
        {
            #[allow(clippy::cast_ptr_alignment)]
            let address = &*address.lpSockaddr.cast::<SOCKADDR_IN>();
            let octets = address.sin_addr.S_un.S_un_b;
            return Some((
                family,
                Ipv4Addr::new(octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4).to_string(),
            ));
        }
        if family == AF_INET6
            && address.iSockaddrLength >= i32::try_from(size_of::<SOCKADDR_IN6>()).ok()?
        {
            #[allow(clippy::cast_ptr_alignment)]
            let address = &*address.lpSockaddr.cast::<SOCKADDR_IN6>();
            return Some((family, Ipv6Addr::from(address.sin6_addr.u.Byte).to_string()));
        }
        None
    }

    unsafe fn wide_string(value: *mut u16) -> String {
        if value.is_null() {
            return String::new();
        }
        let mut length = 0_usize;
        while length < 32_768 && *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_windows_network_observation_is_explicitly_unsupported() {
        #[cfg(not(windows))]
        assert!(matches!(
            super::audit_network_inventory(),
            Err(super::PlatformError::UnsupportedPlatform)
        ));
    }
}
