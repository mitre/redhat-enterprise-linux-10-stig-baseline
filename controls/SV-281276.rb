control 'SV-281276' do
  title 'RHEL 10 must prevent a user from overriding the disabling of the graphical user smart card removal action.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 10 must provide users with the ability to manually invoke a session lock so users can secure their session if they must temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

Verify RHEL 10 disables ability of the user to override the smart card removal action setting with the following command:

$ gsettings writable org.gnome.settings-daemon.peripherals.smartcard removal-action
false

If "removal-action" is writable and the result is "true", this is a finding.'
  desc 'fix', 'Configure RHEL 10 to prevent a user from overriding the disabling of the graphical user smart card removal action.

Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user override of the smart card removal action:

/org/gnome/settings-daemon/peripherals/smartcard/removal-action

Update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-85837r1166778_chk'
  tag severity: 'medium'
  tag gid: 'V-281276'
  tag rid: 'SV-281276r1166780_rule'
  tag stig_id: 'RHEL-10-700730'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-85742r1166779_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058', 'CCI-000057']
  tag nist: ['AC-11 b', 'AC-11 a']
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
    output = command('gsettings writable org.gnome.settings-daemon.peripherals.smartcard removal-action').stdout.strip
    describe 'Users should not be able to override the smart card removal action setting' do
      subject { output }
      it { should cmp 'false' }
    end
  end
end
