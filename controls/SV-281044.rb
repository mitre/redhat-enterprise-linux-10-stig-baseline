control 'SV-281044' do
  title 'RHEL 10 must be configured so that cron configuration files directories are group-owned by root.'
  desc 'Service configuration files enable or disable features of their respective services, which if configured incorrectly can lead to insecure and vulnerable configurations. Therefore, service configuration files should be owned by the correct group to prevent unauthorized changes.'
  desc 'check', 'Verify RHEL 10 group ownership of all cron configuration files with the following command:

$ stat -c "%G %n" /etc/cron*
root /etc/cron.d
root /etc/cron.daily
root /etc/cron.deny
root /etc/cron.hourly
root /etc/cron.monthly
root /etc/crontab
root /etc/cron.weekly

If any crontab is not group-owned by "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that any cron configuration file directories are group-owned by "root" with the following command:

$ sudo chgrp root [cron config file]'
  impact 0.5
  tag check_id: 'C-85605r1165485_chk'
  tag severity: 'medium'
  tag gid: 'V-281044'
  tag rid: 'SV-281044r1184618_rule'
  tag stig_id: 'RHEL-10-400135'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85510r1165486_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  crontabs = command('stat -c "%U %n" /etc/cron*').stdout.split("\n")

  failing_crontabs = crontabs.reject { |c| file(c.split[1]).grouped_into?('root') }

  describe 'Crontabs' do
    it 'should be group owned by root' do
      expect(failing_crontabs).to be_empty, "Failing crontabs:\n\t- #{failing_crontabs.join("\n\t- ")}"
    end
  end
end
