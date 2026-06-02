control 'SV-281274' do
  title 'RHEL 10 must prevent a user from overriding the disabling of the graphical user interface autorun function.'
  desc 'Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., Transport Layer Security [TLS], WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

Verify RHEL 10 disables ability of the user to override the graphical user interface autorun setting.

Check that the autorun setting is set to prevent user modification with the following command:

$ gsettings writable org.gnome.desktop.media-handling autorun-never
false

If "autorun-never" is writable, the result is "true". 

If this is not documented with the information system security officer as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the GNOME desktop does not allow a user to change the setting that disables autorun on removable media.

Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

Update the "/etc/dconf/db/local.d/locks/00-security-settings-lock" file to prevent user modification:

$ sudo vi /etc/dconf/db/local.d/locks/00-security-settings-lock

/org/gnome/desktop/media-handling/autorun-never

Update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-85835r1166772_chk'
  tag severity: 'medium'
  tag gid: 'V-281274'
  tag rid: 'SV-281274r1197245_rule'
  tag stig_id: 'RHEL-10-700710'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-85740r1166773_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3']
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
    output = command('gsettings writable org.gnome.desktop.media-handling autorun-never').stdout.strip
    describe 'Users should not be able to override the graphical user interface autorun setting' do
      subject { output }
      it { should cmp 'false' }
    end
  end
end
