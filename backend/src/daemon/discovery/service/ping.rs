use crate::daemon::discovery::service::base::{
    CreatesDiscoveredEntities, DiscoversNetworkedEntities, Discovery, HasDiscoveryType,
    SCAN_TIMEOUT,
};
use crate::daemon::discovery::types::base::{DiscoveryCriticalError, DiscoverySessionUpdate};
use crate::server::discovery::types::base::DiscoveryType;
use crate::server::hosts::types::{
    interfaces::{Interface, InterfaceBase},
    ports::PortBase,
};
use crate::server::services::types::base::ServiceMatchBaselineParams;
use crate::server::subnets::types::base::SubnetTypeDiscriminants;
use crate::{
    daemon::utils::base::DaemonUtils,
    server::{
        daemons::types::api::DaemonDiscoveryRequest,
        hosts::types::base::Host,
        services::types::endpoints::EndpointResponse,
        subnets::types::base::{Subnet, SubnetType},
    },
};
use anyhow::anyhow;
use anyhow::{Error, Result};
use async_trait::async_trait;
use cidr::IpCidr;
use futures::{
    future::try_join_all,
    stream::{self, StreamExt},
};
use std::net::{IpAddr, Ipv4Addr};
use std::result::Result::Ok;
use std::sync::Arc;
use strum::IntoDiscriminant;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct PingScanDiscovery {}

impl HasDiscoveryType for Discovery<PingScanDiscovery> {
    fn discovery_type(&self) -> DiscoveryType {
        DiscoveryType::Ping
    }
}

impl CreatesDiscoveredEntities for Discovery<PingScanDiscovery> {}

#[async_trait]
impl DiscoversNetworkedEntities for Discovery<PingScanDiscovery> {
    async fn start_discovery_session(
        &self,
        request: DaemonDiscoveryRequest,
        cancel: CancellationToken,
    ) -> Result<(), Error> {
        // Get subnets for ping scanning
        let subnets: Vec<Subnet> = self.discover_create_subnets().await?;

        let total_ips_across_subnets: usize = subnets
            .iter()
            .map(|subnet| subnet.base.cidr.iter().count())
            .sum();

        self.start_discovery(total_ips_across_subnets, request)
            .await?;

        let discovery_futures = subnets
            .iter()
            .map(|subnet| self.ping_scan_and_process_hosts(subnet, cancel.clone()));

        let discovery_result = try_join_all(discovery_futures).await.map(|_| ());

        self.finish_discovery(discovery_result, cancel.clone())
            .await?;

        Ok(())
    }

    async fn get_gateway_ips(&self) -> Result<Vec<IpAddr>, Error> {
        self.as_ref()
            .utils
            .get_own_routing_table_gateway_ips()
            .await
    }

    async fn discover_create_subnets(&self) -> Result<Vec<Subnet>, Error> {
        let daemon_id = self.as_ref().config_store.get_id().await?;
        let network_id = self
            .as_ref()
            .config_store
            .get_network_id()
            .await?
            .ok_or_else(|| anyhow::anyhow!("Network ID not set"))?;

        let (_, subnets) = self
            .as_ref()
            .utils
            .get_own_interfaces(self.discovery_type(), daemon_id, network_id)
            .await?;

        // Filter out docker bridge subnets, those are handled in docker discovery
        let subnets: Vec<Subnet> = subnets
            .into_iter()
            .filter(|s| s.base.subnet_type.discriminant() != SubnetTypeDiscriminants::DockerBridge)
            .collect();

        let subnet_futures = subnets.iter().map(|subnet| self.create_subnet(subnet));
        let subnets = try_join_all(subnet_futures).await?;

        Ok(subnets)
    }
}

impl Discovery<PingScanDiscovery> {
    /// Scan subnet using ICMP ping and process hosts that respond
    async fn ping_scan_and_process_hosts(
        &self,
        subnet: &Subnet,
        cancel: CancellationToken,
    ) -> Result<Vec<Host>> {
        tracing::info!(
            "Scanning subnet {} with ICMP ping for active hosts",
            subnet.base.cidr
        );

        let concurrent_pings = self.as_ref().config_store.get_concurrent_scans().await?;
        tracing::info!("Using up to {} concurrent pings", concurrent_pings);

        let session = self.as_ref().get_session().await?;
        let scanned_count = session.scanned_count.clone();
        let discovered_count: Arc<std::sync::atomic::AtomicUsize> =
            session.discovered_count.clone();

        // Report initial progress
        self.report_discovery_update(DiscoverySessionUpdate::scanning(0, 0))
            .await?;

        // Process all IPs with ping, then scan responsive hosts for ports
        let results = stream::iter(self.determine_ping_scan_order(&subnet.base.cidr))
            .map(async |ip| {
                let cancel = cancel.clone();
                let subnet = subnet.clone();
                let scanned_count = scanned_count.clone();

                // First, ping the host to see if it's online
                match self.ping_host(ip, cancel.clone()).await {
                    Ok(true) => {
                        // Host responded to ping, now scan for ports and services
                        match self.scan_host(ip, scanned_count, cancel.clone()).await {
                            Ok(None) => Ok(None),
                            Err(e) => Err(e),
                            Ok(Some((all_ports, endpoint_responses))) => {
                                let hostname = self.get_hostname_for_ip(ip).await?;

                                let mac = match subnet.base.subnet_type {
                                    SubnetType::VpnTunnel => None, // ARP doesn't work through VPN tunnels
                                    _ => self.as_ref().utils.get_mac_address_for_ip(ip).await?,
                                };

                                let interface = Interface::new(InterfaceBase {
                                    name: None,
                                    subnet_id: subnet.id,
                                    ip_address: ip,
                                    mac_address: mac,
                                });

                                if let Ok(Some((host, services))) = self
                                    .process_host(
                                        ServiceMatchBaselineParams {
                                            subnet: &subnet,
                                            interface: &interface,
                                            all_ports: &all_ports,
                                            endpoint_responses: &endpoint_responses,
                                            virtualization: &None,
                                        },
                                        hostname,
                                    )
                                    .await
                                {
                                    discovered_count
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    if let Ok((created_host, _)) =
                                        self.create_host(host, services).await
                                    {
                                        return Ok::<Option<Host>, Error>(Some(created_host));
                                    }
                                }
                                Ok(None)
                            }
                        }
                    }
                    Ok(false) => {
                        // Host didn't respond to ping
                        scanned_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok(None)
                    }
                    Err(e) => {
                        if DiscoveryCriticalError::is_critical_error(e.to_string()) {
                            Err(e)
                        } else {
                            scanned_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            Ok(None)
                        }
                    }
                }
            })
            .buffer_unordered(concurrent_pings);

        // Consume the stream and report progress periodically
        tracing::info!(
            "Ping scan stream created for subnet {}, starting consumption",
            subnet.base.cidr
        );
        let mut stream_pin = Box::pin(results);
        let mut last_reported_scan_count: usize = 0;
        let mut last_reported_discovery_count: usize = 0;
        let mut successful_discoveries = Vec::new();

        while let Some(result) = stream_pin.next().await {
            if cancel.is_cancelled() {
                tracing::warn!("Ping discovery session was cancelled");
                return Err(Error::msg("Discovery session was cancelled"));
            }

            match result {
                Ok(Some(host)) => successful_discoveries.push(host),
                Ok(None) => {}
                Err(e) => {
                    // Check if this is a critical error (resource exhaustion)
                    if DiscoveryCriticalError::is_critical_error(e.to_string()) {
                        return Err(e); // Propagate the error up
                    } else {
                        // Non-critical errors just get logged
                        tracing::warn!("Error during ping scanning/processing: {}", e);
                    }
                }
            }

            (last_reported_scan_count, last_reported_discovery_count) = self
                .periodic_scan_update(20, last_reported_scan_count, last_reported_discovery_count)
                .await?;
        }

        tracing::info!("Completed ping scanning subnet {}", subnet.base.cidr);
        Ok(successful_discoveries)
    }

    /// Send an ICMP ping to a host and return true if it responds
    async fn ping_host(&self, ip: IpAddr, cancel: CancellationToken) -> Result<bool, Error> {
        if cancel.is_cancelled() {
            return Err(Error::msg("Ping discovery was cancelled"));
        }

        let ipv4_addr = match ip {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                // For now, we don't support IPv6 ping
                return Ok(false);
            }
        };

        // Use a blocking task for the ping operation since pnet is sync
        let ping_result = tokio::task::spawn_blocking(move || Self::ping_host_sync(ipv4_addr))
            .await
            .map_err(|e| anyhow!("Ping task panicked: {}", e))?;

        match ping_result {
            Ok(true) => {
                tracing::debug!("Host {} responded to ping", ip);
                Ok(true)
            }
            Ok(false) => {
                tracing::debug!("Host {} did not respond to ping", ip);
                Ok(false)
            }
            Err(e) => {
                tracing::debug!("Error pinging host {}: {}", ip, e);
                if DiscoveryCriticalError::is_critical_error(e.to_string()) {
                    Err(e)
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Synchronous ping implementation using system ping command
    fn ping_host_sync(ip: Ipv4Addr) -> Result<bool, Error> {
        // Use system ping command instead of raw sockets for better compatibility
        let ip_str = ip.to_string();
        let output = if cfg!(target_os = "windows") {
            // Windows ping command syntax
            std::process::Command::new("ping")
                .args(["-n", "1", "-w", "1000", &ip_str])
                .output()
                .map_err(|e| anyhow!("Failed to execute ping command: {}", e))?
        } else {
            // Unix/Linux ping command syntax
            std::process::Command::new("ping")
                .args(["-c", "1", "-W", "1", &ip_str])
                .output()
                .map_err(|e| anyhow!("Failed to execute ping command: {}", e))?
        };

        // Check if ping was successful (exit code 0)
        Ok(output.status.success())
    }

    async fn get_hostname_for_ip(&self, ip: IpAddr) -> Result<Option<String>, Error> {
        match timeout(SCAN_TIMEOUT, async {
            tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip)).await?
        })
        .await
        {
            Ok(Ok(hostname)) => Ok(Some(hostname)),
            _ => Ok(None),
        }
    }

    /// Determine the order to ping IPs - prioritize likely active hosts
    fn determine_ping_scan_order(&self, subnet: &IpCidr) -> impl Iterator<Item = IpAddr> {
        let mut ips: Vec<IpAddr> = subnet.iter().map(|ip| ip.address()).collect();

        // Sort by likelihood of being active hosts - same logic as network scan
        ips.sort_by_key(|ip| {
            let last_octet = match ip {
                IpAddr::V4(ipv4) => ipv4.octets()[3],
                IpAddr::V6(_) => return 9999, // IPv6 gets lowest priority for now
            };

            match last_octet {
                // Tier 1: Almost guaranteed to be active infrastructure
                1 => 1,   // Default gateway (.1)
                254 => 2, // Alternative gateway (.254)

                // Tier 2: Very common infrastructure and static assignments
                2 => 10,   // Secondary router/switch
                3 => 11,   // Tertiary infrastructure
                10 => 12,  // Common DHCP start
                100 => 13, // Common DHCP end
                253 => 14, // Alt gateway range
                252 => 15, // Alt gateway range

                // Tier 3: Common static device ranges
                4..=9 => 20 + last_octet as u16, // Infrastructure devices
                11..=20 => 30 + last_octet as u16, // Servers, printers
                21..=30 => 50 + last_octet as u16, // Network devices

                // Tier 4: Active DHCP ranges (most devices live here)
                31..=50 => 100 + last_octet as u16, // Early DHCP range
                51..=100 => 200 + last_octet as u16, // Mid DHCP range
                101..=150 => 400 + last_octet as u16, // Late DHCP range

                // Tier 5: Less common but still viable
                151..=200 => 600 + last_octet as u16, // Extended DHCP
                201..=251 => 800 + last_octet as u16, // High static range

                // Skip entirely - reserved addresses
                0 | 255 => 9998, // Network/broadcast addresses
            }
        });

        ips.into_iter()
    }

    /// Reuse the scan_host method from network discovery for port scanning responsive hosts
    pub async fn scan_host(
        &self,
        ip: IpAddr,
        scanned_count: Arc<std::sync::atomic::AtomicUsize>,
        cancel: CancellationToken,
    ) -> Result<Option<(Vec<PortBase>, Vec<EndpointResponse>)>> {
        // Check cancellation at the start
        if cancel.is_cancelled() {
            return Err(Error::msg("Discovery was cancelled"));
        }

        // Scan ports and endpoints
        let scan_result = tokio::spawn(Self::scan_ports_and_endpoints(ip, cancel.clone(), None))
            .await
            .map_err(|e| anyhow!("Scan task panicked: {}", e))?;

        // Check cancellation after network operation
        if cancel.is_cancelled() {
            scanned_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(Error::msg("Discovery was cancelled"));
        }

        match scan_result {
            Ok((open_ports, endpoint_responses)) => {
                if !open_ports.is_empty() || !endpoint_responses.is_empty() {
                    tracing::info!(
                        "Processing ping-responsive host {} with {} open ports and {} endpoint responses",
                        ip,
                        open_ports.len(),
                        endpoint_responses.len()
                    );

                    // Check cancellation before processing
                    if cancel.is_cancelled() {
                        scanned_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Err(Error::msg("Discovery was cancelled"));
                    }

                    Ok(Some((open_ports, endpoint_responses)))
                } else {
                    tracing::debug!("Ping-responsive host {} has no open services", ip);
                    // Still create a host record for ping-responsive devices
                    Ok(Some((vec![], vec![])))
                }
            }
            Err(e) => {
                tracing::debug!("Error scanning ping-responsive host {}: {}", ip, e);

                if DiscoveryCriticalError::is_critical_error(e.to_string()) {
                    Err(e)
                } else {
                    scanned_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(None)
                }
            }
        }
    }
}
