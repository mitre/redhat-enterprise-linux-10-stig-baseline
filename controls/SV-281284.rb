control 'SV-281284' do
  title 'RHEL 10 must prevent a user from overriding the disable-restart-buttons setting for the graphical user interface.'
  desc 'A user who is at the console can reboot the system at the login screen. If restart or shutdown buttons are pressed at the login screen, this can create the risk of short-term loss of availability of systems due to reboot.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

Verify RHEL 10 prevents a user from overriding the disable-restart-buttons setting for graphical user interfaces:

$ gsettings writable org.gnome.login-screen disable-restart-buttons
false

If "disable-restart-buttons" is writable, and the result is "true", this is a finding.'
  desc 'fix', 'Configure RHEL 10 to prevent a user from overriding the disable-restart-buttons setting for graphical user interfaces.

Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

Update the "/etc/dconf/db/local.d/locks/session" file to prevent nonprivileged users from modifying the disable-restart-buttons setting:

$ sudo vi /etc/dconf/db/local.d/locks/session

/org/gnome/login-screen/disable-restart-buttons

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-85845r1197246_chk'
  tag severity: 'medium'
  tag gid: 'V-281284'
  tag rid: 'SV-281284r1197247_rule'
  tag stig_id: 'RHEL-10-700810'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85750r1166803_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002696']
  tag nist: ['CM-6 b', 'SI-6 a']
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
    restart_button_setting = command('gsettings writable org.gnome.login-screen disable-restart-buttons').stdout.strip
    describe 'GUI restart button override must be disabled' do
      subject { restart_button_setting }
      it { should cmp 'false' }
    end
  end
end
