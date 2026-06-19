control 'SV-281323' do
  title 'RHEL 10 must disable file system automount function unless required.'
  desc 'An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.'
  desc 'check', 'Note: If the "autofs" service is not installed, this requirement is not applicable.

Verify RHEL 10 is configured so that the file system automount function has been disabled with the following command:

$ systemctl is-enabled  autofs
masked

If the returned value is not "masked", "disabled", or "not-found" and is not documented as an operational requirement with the information system security officer, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to disable the ability to automount devices.

The "autofs" service can be disabled with the following command:

$ sudo systemctl mask --now autofs.service'
  impact 0.5
  tag check_id: 'C-85884r1167117_chk'
  tag severity: 'medium'
  tag gid: 'V-281323'
  tag rid: 'SV-281323r1167119_rule'
  tag stig_id: 'RHEL-10-701210'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-85789r1167118_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('autofs_required')
    impact 0.0
    describe 'N/A' do
      skip 'Profile inputs indicate that autofs is a documented operational requirement'
    end
  else
    autofs_state = command('systemctl is-enabled autofs').stdout.strip
    autofs_state = systemd_service('autofs').params.LoadState if autofs_state.empty? || autofs_state.start_with?('Failed ')

    describe 'autofs service' do
      it 'is disabled, masked, or not found' do
        expect(%w[disabled masked not-found]).to include(autofs_state)
      end
    end
  end
end
