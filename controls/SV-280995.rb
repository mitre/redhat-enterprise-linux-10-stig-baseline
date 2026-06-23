control 'SV-280995' do
  title 'RHEL 10 must have the "audispd-plugins" package installed.'
  desc 'The "audispd-plugins" package provides plugins for the real-time interface to the audit subsystem, "audispd". These plugins can do such things as relay events to remote machines or analyze events for suspicious behavior.'
  desc 'check', 'Verify RHEL 10 has the "audispd-plugins" package installed with the following command:

$ sudo dnf list --installed audispd-plugins
Installed Packages
audispd-plugins.x86_64                           4.0.3-1.el10                            @rhel-10-for-x86_64-baseos-rpms

If the "audispd-plugins" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "audispd-plugins" package installed with the following command:

$ sudo dnf -y install audispd-plugins'
  impact 0.3
  tag check_id: 'C-85556r1195382_chk'
  tag severity: 'low'
  tag gid: 'V-280995'
  tag rid: 'SV-280995r1195383_rule'
  tag stig_id: 'RHEL-10-200662'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-85461r1165339_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe package('audispd-plugins') do
    it { should be_installed }
  end
end
