control 'SV-280997' do
  title 'RHEL 10 must notify designated personnel if baseline configurations are changed in an unauthorized manner.'
  desc 'The "postfix" package provides the mail command required to allow sending email notifications of unauthorized configuration changes to designated personnel.'
  desc 'check', 'Verify RHEL 10 is configured to allow sending email notifications.

Note: The "postfix" package provides the "mail" command that is used to send email messages.

Verify that the "postfix" package is installed on the system:

$ sudo dnf list --installed postfix
Installed Packages
postfix.x86_64                                         2:3.8.5-8.el10                                         @AppStream

If the "postfix" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to notify designated personnel if baseline configurations are changed in an unauthorized manner.

Install the postfix package with the following command:

$ sudo dnf -y install postfix'
  impact 0.5
  tag check_id: 'C-85558r1195386_chk'
  tag severity: 'medium'
  tag gid: 'V-280997'
  tag rid: 'SV-280997r1195387_rule'
  tag stig_id: 'RHEL-10-200690'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-85463r1165345_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
  tag 'host'
  tag 'container'

  only_if('Alternate system for audit notifications exist, this control is not applicable', impact: 0.0) {
    !input('alt_audit_notification_system')
  }

  describe package('postfix') do
    it { should be_installed }
  end
end
