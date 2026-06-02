control 'SV-281252' do
  title 'RHEL 10 must configure SELinux context type to allow the use of a nondefault faillock tally directory.'
  desc 'Not having the correct SELinux context on the faillock directory may lead to unauthorized access to the directory.'
  desc 'check', 'Note: If the system does not have SELinux enabled and enforcing a targeted policy, or if the pam_faillock module is not configured for use, this requirement is not applicable.

Verify RHEL 10 SELinux context type allows the use of a nondefault faillock tally directory.

Verify the location of the nondefault tally directory for the pam_faillock module with the following command:

$ sudo grep -w dir /etc/security/faillock.conf
dir = /var/log/faillock

Check the security context type of the nondefault tally directory with the following command:

$ ls -Zd /var/log/faillock
unconfined_u:object_r:faillog_t:s0 /var/log/faillock

If the security context type of the nondefault tally directory is not "faillog_t", this is a finding.'
  desc 'fix', 'Configure RHEL 10 to allow the use of a nondefault faillock tally directory while SELinux enforces a targeted policy.

Enable the feature using the following command:

$ sudo authselect enable-feature with-faillock

Create a nondefault faillock tally directory (if it does not already exist) with the following example:

$ sudo mkdir /var/log/faillock

Add/modify the "/etc/security/faillock.conf" file to match the following line:

dir = /var/log/faillock

Update "/etc/selinux/targeted/contexts/files/file_contexts.local" with "faillog_t" context type for the nondefault faillock tally directory with the following command:

$ sudo semanage fcontext -a -t faillog_t "/var/log/faillock(/.*)?"

Update the context type of the nondefault faillock directory/subdirectories and files with the following command:

$ sudo restorecon -R -v /var/log/faillock'
  impact 0.5
  tag check_id: 'C-85813r1166706_chk'
  tag severity: 'medium'
  tag gid: 'V-281252'
  tag rid: 'SV-281252r1166708_rule'
  tag stig_id: 'RHEL-10-700430'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-85718r1166707_fix'
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'

  if %w[docker podman kubepods lxc].include?(virtualization.system)
    impact 0.0
    describe 'Control not applicable in a container' do
      skip 'SELinux controls Not Applicable in a container'
    end
  else

    describe selinux do
      it { should be_installed }
      it { should be_enforcing }
      it { should_not be_disabled }
    end

    describe parse_config_file('/etc/security/faillock.conf') do
      its('dir') { should cmp input('non_default_tally_dir') }
    end

    faillock_tally = input('faillock_tally')

    describe "The selected non-default tally directory for PAM: #{input('non_default_tally_dir')}" do
      subject { file(input('non_default_tally_dir')) }
      its('selinux_label') { should match(/#{faillock_tally}/) }
    end
  end
end
