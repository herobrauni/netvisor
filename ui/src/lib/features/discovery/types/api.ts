export type DiscoveryType =
	| { type: 'SelfReport' }
	| { type: 'Network' }
	| { type: 'Ping' }
	| { type: 'Docker'; host_id: string }
	| { type: 'Proxmox'; host_id: string };

export interface InitiateDiscoveryRequest {
	daemon_id: string;
	discovery_type: DiscoveryType;
}

export interface DiscoverySessionRequest {
	session_id: string;
}

export interface DiscoveryUpdatePayload {
	session_id: string;
	daemon_id: string;
	phase: 'Initiated' | 'Started' | 'Scanning' | 'Complete' | 'Failed' | 'Cancelled';
	completed?: number;
	total?: number;
	discovered_count?: number;
	error?: string;
	started_at?: string;
	finished_at?: string;
}
