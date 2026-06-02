control 'SV-281207' do
  title 'RHEL 10 must restrict privilege elevation to authorized personnel.'
  desc 'If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.'
  desc 'check', 'Verify RHEL 10 restricts privilege elevation to authorized personnel with the following command:

$ sudo grep -riw ALL /etc/sudoers /etc/sudoers.d/ | grep -v "#"

If the either of the following entries is returned, this is a finding:

ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  desc 'fix', 'Configure RHEL 10 to restrict privilege elevation to authorized personnel.

Remove the following entries from the "/etc/sudoers" file or configuration file under "/etc/sudoers.d/":

ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag gid: 'V-281207'
  tag rid: 'SV-281207r1166573_rule'
  tag stig_id: 'RHEL-10-600520'
  tag fix_id: 'F-85673r1166572_fix'
  tag cci: ['CCI-000366', 'CCI-002696']
  tag nist: ['CM-6 b', 'SI-6 a']
  tag 'host'

  only_if('This control is Not Applicable to containers without sudo installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || command('sudo').exist?
  }

  bad_sudoers_rules = sudoers(input('sudoers_config_files').join(' ')).rules.where {
    users == 'ALL' &&
      hosts == 'ALL' &&
      run_as.start_with?('ALL') &&
      commands == 'ALL'
  }

  describe 'Sudoers file(s)' do
    it 'should not contain any unrestricted sudo rules' do
      expect(bad_sudoers_rules.entries).to be_empty, "Unrestricted sudo rules found; check sudoers file(s):\n\t- #{input('sudoers_config_files').join("\n\t- ")}"
    end
  end
end
