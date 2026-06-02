control 'SV-281178' do
  title 'RHEL 10 must ensure that all local interactive user home directories defined in the "/etc/passwd" file must exist.'
  desc 'If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon login. This could create a denial of service because the user would not be able to access their login configuration files, and it may give them visibility to system files they normally would not be able to access.'
  desc 'check', "Verify RHEL 10 interactive users' home directories exist on the system with the following command:

$ sudo pwck -r
user 'mailnull': directory 'var/spool/mqueue' does not exist

The output should not return any interactive users.

If an interactive user's home directory does not exist, this is a finding."
  desc 'fix', %q(Configure RHEL 10 interactive users' home directories to exist on the system.

Create home directories to all local interactive users that do not have a home directory assigned. Use the following commands to create the user home directory assigned in "/etc/ passwd":

Note: The example will be for the user "disauser", who has a home directory of "/home/disauser", a user identifier (UID) of "disauser", and a group identifier (GID) of "users assigned" in "/etc/passwd".

$ sudo mkdir /home/disauser
$ sudo chown disauser /home/disauser
$ sudo chgrp users /home/disauser
$ sudo chmod 0750 /home/disauser)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-281178'
  tag rid: 'SV-281178r1195418_rule'
  tag stig_id: 'RHEL-10-600190'
  tag fix_id: 'F-85644r1166485_fix'
  tag cci: ['CCI-000366', 'CCI-002385']
  tag nist: ['CM-6 b', 'SC-5 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  exempt_home_users = input('exempt_home_users')
  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  iuser_entries = passwd.where { uid.to_i >= uid_min && shell !~ /nologin/ && !exempt_home_users.include?(user) }

  if !iuser_entries.users.nil? && !iuser_entries.users.empty?
    failing_homedirs = iuser_entries.homes.reject { |home|
      file(home).exist?
    }
    describe 'All non-exempt interactive user account home directories on the system' do
      it 'should exist' do
        expect(failing_homedirs).to be_empty, "Failing home directories:\n\t- #{failing_homedirs.join("\n\t- ")}"
      end
    end
  else
    describe 'No non-exempt interactive user accounts' do
      it 'were detected on the system' do
        expect(true).to eq(true)
      end
    end
  end
end
