control 'SV-281206' do
  title 'RHEL 10 must be configured to not bypass password requirements for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization. When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.'
  desc 'check', 'Verify RHEL 10 is not configured to bypass password requirements for privilege escalation with the following command:

$ sudo grep pam_succeed_if /etc/pam.d/sudo

If any occurrences of "pam_succeed_if" are returned, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to require users to supply a password for privilege escalation.

Remove any occurrences of " pam_succeed_if " in the "/etc/pam.d/sudo" file.'
  impact 0.5
  tag check_id: 'C-85767r1166568_chk'
  tag severity: 'medium'
  tag gid: 'V-281206'
  tag rid: 'SV-281206r1166570_rule'
  tag stig_id: 'RHEL-10-600510'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-85672r1166569_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'
  tag 'container-conditional'

  if %w[docker podman kubepods lxc].include?(virtualization.system) && !command('sudo').exist?
    impact 0.0
    describe 'Control not applicable within a container without sudo enabled' do
      skip 'Control not applicable within a container without sudo enabled'
    end
  else
    describe parse_config_file('/etc/pam.d/sudo') do
      its('content') { should_not match(/pam_succeed_if/) }
    end
  end
end
