control 'SV-280984' do
  title 'RHEL 10 must have the rsyslog service set to active.'
  desc 'The rsyslog service must be running to provide logging services, which are essential to system administration.'
  desc 'check', 'Verify RHEL 10 rsyslog is active with the following command:

$ systemctl is-active rsyslog
active

If the rsyslog service is not active, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enable the rsyslog service with the following command:

$ sudo systemctl enable --now rsyslog'
  impact 0.5
  tag check_id: 'C-85545r1165305_chk'
  tag severity: 'medium'
  tag gid: 'V-280984'
  tag rid: 'SV-280984r1165307_rule'
  tag stig_id: 'RHEL-10-200641'
  tag gtitle: 'SRG-OS-000040-GPOS-00018'
  tag fix_id: 'F-85450r1165306_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end
