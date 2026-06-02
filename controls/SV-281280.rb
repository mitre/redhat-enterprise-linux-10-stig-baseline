control 'SV-281280' do
  title 'RHEL 10 must initiate a session lock for graphical user interfaces when the screensaver is activated.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to logout because of the temporary nature of the absence.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

Verify RHEL 10 initiates a session lock for graphical user interfaces when the screensaver is activated with the following command:

$ gsettings get org.gnome.desktop.screensaver lock-delay
uint32 5

If the "uint32" setting is not set to "5" or less, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to initiate a session lock for graphical user interfaces when a screensaver is activated.

Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

Create a database to contain the systemwide screensaver settings (if it does not already exist) with the following command:

$ sudo vi /etc/dconf/db/local.d/00-screensaver

[org/gnome/desktop/screensaver]
lock-delay=uint32 5

The "uint32" must be included along with the integer key values as shown.

Update the system databases:

$ sudo dconf update'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-281280'
  tag rid: 'SV-281280r1166792_rule'
  tag stig_id: 'RHEL-10-700770'
  tag fix_id: 'F-85746r1166791_fix'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 a', 'AC-11 (1)']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  no_gui = command('ls /usr/share/xsessions/*').stderr.match?(/No such file or directory/)

  if no_gui
    impact 0.0
    describe 'The system does not have a GUI Desktop is installed; this control is Not Applicable' do
      skip 'A GUI desktop is not installed; this control is Not Applicable.'
    end
  else
    describe command('gsettings get org.gnome.desktop.screensaver lock-delay') do
      its('stdout.strip') { should match(/uint32\s[0-5]/) }
    end
  end
end
