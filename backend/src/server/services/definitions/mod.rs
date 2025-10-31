use crate::server::services::types::definitions::ServiceDefinition;
use crate::server::shared::types::metadata::HasId;
use inventory;

#[derive(Debug, Clone, Copy)]
pub struct ServiceDefinitionFactory(pub fn() -> Box<dyn ServiceDefinition>);

impl ServiceDefinitionFactory {
    pub const fn new(factory: fn() -> Box<dyn ServiceDefinition>) -> Self {
        Self(factory)
    }

    pub fn create(&self) -> Box<dyn ServiceDefinition> {
        (self.0)()
    }
}

pub fn create_service<T>() -> Box<dyn ServiceDefinition>
where
    T: ServiceDefinition + Default + 'static,
{
    Box::new(T::default())
}

inventory::collect!(ServiceDefinitionFactory);

pub struct ServiceDefinitionRegistry;

impl ServiceDefinitionRegistry {
    /// Get all registered services as instances
    pub fn all_service_definitions() -> Vec<Box<dyn ServiceDefinition>> {
        inventory::iter::<ServiceDefinitionFactory>()
            .map(|factory| factory.create())
            .collect()
    }

    pub fn service_exists(id: &str) -> bool {
        inventory::iter::<ServiceDefinitionFactory>().any(|factory| factory.create().id() == id)
    }

    pub fn find_by_id(id: &str) -> Option<Box<dyn ServiceDefinition>> {
        inventory::iter::<ServiceDefinitionFactory>().find_map(|factory| {
            let service_definition = factory.create();
            if service_definition.id() == id {
                Some(service_definition)
            } else {
                None
            }
        })
    }
}

pub mod access_point;
pub mod adguard_home;
pub mod amazon_echo;
pub mod bind9;
pub mod chromecast;
pub mod client;
pub mod cloudflared;
pub mod cups;
pub mod dhcp_server;
pub mod dns_server;
pub mod docker_container;
pub mod docker_daemon;
pub mod docker_swarm;
pub mod duplicati;
pub mod eero_gateway;
pub mod eero_repeater;
pub mod emby;
pub mod file_server;
pub mod fios_extender;
pub mod fios_gateway;
pub mod firewall;
pub mod fortigate;
pub mod gateway;
pub mod google_home;
pub mod google_nest_repeater;
pub mod google_nest_router;
pub mod grafana;
pub mod home_assistant;
pub mod hp_printer;
pub mod jellyfin;
pub mod kubernetes;
pub mod nas_device;
pub mod nest_protect;
pub mod nest_thermostat;
pub mod netvisor_daemon;
pub mod netvisor_server;
pub mod next_cloud;
pub mod nginx_proxy_manager;
pub mod open_media_vault;
pub mod opn_sense;
pub mod pf_blocker_ng;
pub mod pf_sense;
pub mod philips_hue_bridge;
pub mod pi_hole;
pub mod plex;
pub mod portainer;
pub mod power_dns;
pub mod print_server;
pub mod prometheus;
pub mod proxmox;
pub mod qnap;
pub mod restic;
pub mod ring_doorbell;
pub mod roku;
pub mod sonos_speaker;
pub mod ssh_server;
pub mod switch;
pub mod syncthing;
pub mod synology;
pub mod tp_link_eap;
pub mod traefik;
pub mod true_nas;
pub mod unbound;
pub mod unifi_access_point;
pub mod unifi_controller;
pub mod uptime_kuma;
pub mod web_service;
pub mod wg_dashboard;
pub mod workstation;
