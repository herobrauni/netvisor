<script lang="ts">
	import { pushError, pushSuccess } from '$lib/shared/stores/feedback';
	import EditModal from '$lib/shared/components/forms/EditModal.svelte';
	import ModalHeaderIcon from '$lib/shared/components/layout/ModalHeaderIcon.svelte';
	import { entities } from '$lib/shared/stores/metadata';
	import type { Daemon } from '../types/base';
	import { updateDaemonIp } from '../store';
	import { Edit } from 'lucide-svelte';

	export let isOpen = false;
	export let onClose: () => void;
	export let daemon: Daemon | null = null;

	let ipInput = '';
	let portInput = '';

	$: if (daemon && isOpen) {
		ipInput = daemon.ip;
		portInput = daemon.port.toString();
	}

	function handleOnClose() {
		ipInput = '';
		portInput = '';
		onClose();
	}

	async function handleUpdateIp() {
		if (!daemon) {
			pushError('No daemon provided');
			return;
		}

		const port = parseInt(portInput);
		if (isNaN(port) || port < 1 || port > 65535) {
			pushError('Please enter a valid port number (1-65535)');
			return;
		}

		// Basic IP validation
		const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
		if (!ipRegex.test(ipInput)) {
			pushError('Please enter a valid IP address');
			return;
		}

		try {
			const updatedDaemon = await updateDaemonIp(daemon.id, ipInput, port);
			if (updatedDaemon) {
				pushSuccess(`Daemon IP updated to ${ipInput}:${port}`);
				handleOnClose();
			}
		} catch (error) {
			pushError('Failed to update daemon IP');
		}
	}

	let colorHelper = entities.getColorHelper('Daemon');
</script>

<EditModal
	{isOpen}
	title="Update Daemon IP"
	cancelLabel="Cancel"
	saveLabel="Update"
	onCancel={handleOnClose}
	onSave={handleUpdateIp}
	size="md"
>
	<!-- Header icon -->
	<svelte:fragment slot="header-icon">
		<ModalHeaderIcon Icon={Edit} color={colorHelper.string} />
	</svelte:fragment>

	<div class="space-y-4">
		<h3 class="text-primary text-lg font-medium">
			Update IP Address and Port
		</h3>

		{#if daemon}
			<div class="text-secondary mb-4">
				<p>Updating connection details for daemon: <strong>{daemon.ip}:{daemon.port}</strong></p>
			</div>

			<div class="space-y-4">
				<div>
					<label for="ip-input" class="block text-sm font-medium text-gray-700 mb-1">
						IP Address
					</label>
					<input
						id="ip-input"
						type="text"
						bind:value={ipInput}
						placeholder="192.168.1.100"
						class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
					/>
				</div>

				<div>
					<label for="port-input" class="block text-sm font-medium text-gray-700 mb-1">
						Port
					</label>
					<input
						id="port-input"
						type="number"
						bind:value={portInput}
						placeholder="60073"
						min="1"
						max="65535"
						class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
					/>
				</div>
			</div>

			<div class="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
				<p class="text-sm text-yellow-800">
					<strong>Note:</strong> After updating the IP, make sure the daemon is running at the new address and port.
				</p>
			</div>
		{:else}
			<div class="text-secondary">
				<p>No daemon selected for IP update.</p>
			</div>
		{/if}
	</div>
</EditModal>