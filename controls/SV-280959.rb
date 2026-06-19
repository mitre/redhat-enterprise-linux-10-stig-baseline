control 'SV-280959' do
  title 'RHEL 10 must enable the chronyd service.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Verify RHEL 10 sets the chronyd service to active with the following command:

$ systemctl is-active chronyd
active

If the chronyd service is not active, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enable the chronyd service with the following command:

$ sudo systemctl enable --now chronyd'
  impact 0.5
  tag check_id: 'C-85520r1165230_chk'
  tag severity: 'medium'
  tag gid: 'V-280959'
  tag rid: 'SV-280959r1165232_rule'
  tag stig_id: 'RHEL-10-200541'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-85425r1165231_fix'
  tag 'documentable'
  tag cci: ['CCI-004923']
  tag nist: ['SC-45 (1) (a)']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe service('chronyd') do
    it { should be_enabled }
    it { should be_running }
  end
end
