control 'SV-280954' do
  title 'RHEL 10 must have the "s-nail" package installed.'
  desc 'The "s-nail" package provides the mail command required to allow sending email notifications of unauthorized configuration changes to designated personnel.'
  desc 'check', 'Verify RHEL 10 is configured to allow sending email notifications.

Verify the "s-nail" package is installed on the system with the following command:

$ sudo dnf list --installed s-nail
Installed Packages
s-nail.x86_64                             14.9.24-12.el10                             @rhel-10-for-x86_64-appstream-rpms

If the "s-nail" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "s-nail" package installed with the following command:

$ sudo dnf -y install s-nail'
  impact 0.5
  tag check_id: 'C-85515r1195343_chk'
  tag severity: 'medium'
  tag gid: 'V-280954'
  tag rid: 'SV-280954r1195344_rule'
  tag stig_id: 'RHEL-10-200520'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-85420r1165216_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
  tag 'host'
  tag 'container'

  mail_package = input('mail_package')

  describe package(mail_package) do
    it { should be_installed }
  end
end
