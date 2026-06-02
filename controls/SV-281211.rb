control 'SV-281211' do
  title 'RHEL 10 must require users to provide a password for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical that the user reauthenticate.'
  desc 'check', %q(Verify RHEL 10 has no occurrences of "NOPASSWD" in "/etc/sudoers" with the following command:

$ sudo grep -ir nopasswd /etc/sudoers /etc/sudoers.d/ | grep -v '#'

If any occurrences of "NOPASSWD" are returned from the command and have not been documented with the information system security officer as an organizationally defined administrative group using multifactor authentication, this is a finding.)
  desc 'fix', %q(Configure RHEL 10 to not allow users to execute privileged actions without authenticating with a password.

Remove any occurrence of "NOPASSWD" found in the "/etc/sudoers" file or files in the "/etc/sudoers.d" directory:

$ sudo find /etc/sudoers /etc/sudoers.d -type f -exec sed -i '/NOPASSWD/ s/^/# /g' {} \;)
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-281211'
  tag rid: 'SV-281211r1166585_rule'
  tag stig_id: 'RHEL-10-600560'
  tag fix_id: 'F-85677r1166584_fix'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable within a container without sudo installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || command('sudo').exist?
  }

  # TODO: figure out why this .where throws an exception if we don't explicitly filter out nils via 'tags.nil?'
  # ergo shouldn't the filtertable be handling that kind of nil-checking for us?
  failing_results = sudoers(input('sudoers_config_files').join(' ')).rules.where { tags.nil? && (tags || '').include?('NOPASSWD') }

  failing_results = failing_results.where { !input('passwordless_admins').include?(users) } if input('passwordless_admins').nil?

  describe 'Sudoers' do
    it 'should not include any (non-exempt) users with NOPASSWD set' do
      expect(failing_results.users).to be_empty, "NOPASSWD settings found for users:\n\t- #{failing_results.users.join("\n\t- ")}"
    end
  end
end
