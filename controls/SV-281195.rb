control 'SV-281195' do
  title 'RHEL 10 must automatically lock the root account until the root account is released by an administrator when three unsuccessful login attempts occur during a 15-minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, also known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify RHEL 10 is configured to lock the root account after three unsuccessful login attempts with the following command:

$ sudo grep even_deny_root /etc/security/faillock.conf
even_deny_root

If the "even_deny_root" option is not set or is missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to lock out the "root" account after a number of incorrect login attempts using "pam_faillock.so".

Enable the feature using the following command:

$ sudo authselect enable-feature with-faillock

Edit the "/etc/security/faillock.conf" by uncommenting or adding the following line:

even_deny_root'
  impact 0.5
  tag check_id: 'C-85756r1166535_chk'
  tag severity: 'medium'
  tag gid: 'V-281195'
  tag rid: 'SV-281195r1166537_rule'
  tag stig_id: 'RHEL-10-600415'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-85661r1166536_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe command('grep even_deny_root /etc/security/faillock.conf').stdout.strip do
    it { should match(/^even_deny_root$/) }
  end
end
