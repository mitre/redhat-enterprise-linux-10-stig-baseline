control 'SV-281339' do
  title 'RHEL 10 must not have unauthorized IP tunnels configured.'
  desc 'IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the information system security officer (ISSO).'
  desc 'check', 'Verify RHEL 10 does not have unauthorized IP tunnels configured.

Determine if the IPsec service is active with the following command:

$ systemctl is-active ipsec
Inactive

If the IPsec service is active, check for configured IPsec connections ("conn"), with the following command:

$ sudo grep -rni conn /etc/ipsec.conf /etc/ipsec.d/

Verify any returned results are documented with the ISSO.

If the IPsec tunnels are active and not approved, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not have unauthorized IP tunnels configured.

Remove all unapproved tunnels from the system, or document them with the ISSO.'
  impact 0.5
  tag check_id: 'C-85900r1167165_chk'
  tag severity: 'medium'
  tag gid: 'V-281339'
  tag rid: 'SV-281339r1167167_rule'
  tag stig_id: 'RHEL-10-800070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85805r1167166_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000213']
  tag nist: ['CM-6 b', 'AC-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe service('ipsec') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
