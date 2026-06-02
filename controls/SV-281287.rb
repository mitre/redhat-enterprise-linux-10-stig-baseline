control 'SV-281287' do
  title 'RHEL 10 must disable the user list at login for graphical user interfaces.'
  desc 'Leaving the user list enabled is a security risk because it allows anyone with physical access to the system to enumerate known user accounts without authenticated access to the system.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

Verify RHEL 10 disables the user login list for graphical user interfaces with the following command:

$ gsettings get org.gnome.login-screen disable-user-list
true

If the setting is "false", this is a finding.'
  desc 'fix', 'Configure RHEL 10 to disable the user list at login for graphical user interfaces.

Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

Create a database to contain the systemwide screensaver settings (if it does not already exist) with the following command:

$ sudo vi /etc/dconf/db/local.d/02-login-screen

[org/gnome/login-screen]
disable-user-list=true

Update the system databases:

$ sudo dconf update'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-281287'
  tag rid: 'SV-281287r1166813_rule'
  tag stig_id: 'RHEL-10-700840'
  tag fix_id: 'F-85753r1166812_fix'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  no_gui = command('ls /usr/share/xsessions/*').stderr.match?(/No such file or directory/)

  if no_gui
    impact 0.0
    describe 'The system does not have a GUI installed, this requirement is Not Applicable.' do
      skip 'A GUI desktop is not installed; this control is Not Applicable.'
    end
  else
    describe command('gsettings get org.gnome.login-screen disable-user-list') do
      its('stdout.strip') { should cmp 'true' }
    end
  end
end
