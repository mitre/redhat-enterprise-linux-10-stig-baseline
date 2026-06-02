control 'SV-281292' do
  title 'RHEL 10 must disable the graphical user interface autorunner unless required.'
  desc 'Automatically running applications when media is inserted allows for the easy introduction of unknown data, thereby facilitating malicious activity.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

Verify RHEL 10 disables the graphical user interface autorun function.

Disable the setting with the following command:

$ gsettings get org.gnome.desktop.media-handling autorun-never
true

If "autorun-never" is set to "false" and is not documented with the information system security officer as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 10 GNOME to disable autorunning of removable media.

Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

Update the "/etc/dconf/db/local.d/00-security-settings" database to disable the GUI autorun function:

$ sudo vi /etc/dconf/db/local.d/00-security-settings

[org/gnome/desktop/media-handling]
autorun-never=true

Update the dconf system databases:

$ sudo dconf update'
  impact 0.3
  tag check_id: 'C-85853r1166826_chk'
  tag severity: 'low'
  tag gid: 'V-281292'
  tag rid: 'SV-281292r1166828_rule'
  tag stig_id: 'RHEL-10-700890'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-85758r1166827_fix'
  tag 'documentable'
  tag cci: ['CCI-001764', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-7 (2)', 'IA-3']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('gui_autorun_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    no_gui = command('ls /usr/share/xsessions/*').stderr.match?(/No such file or directory/)

    if no_gui
      impact 0.0
      describe 'The system does not have a GUI Desktop is installed; this control is Not Applicable' do
        skip 'A GUI desktop is not installed; this control is Not Applicable.'
      end
    else
      describe command('gsettings get org.gnome.desktop.media-handling autorun-never') do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  end
end
