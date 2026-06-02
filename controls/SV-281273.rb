control 'SV-281273' do
  title 'RHEL 10 must prevent a user from overriding the disabling of the graphical user interface automount function.'
  desc 'Without identifying and authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', %q(Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

Verify RHEL 10 disables the ability of the user to override the graphical user interface automount setting.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user
system-db:local

Check that the automount setting is locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ sudo grep 'automount-open' /etc/dconf/db/local.d/locks/*
/org/gnome/desktop/media-handling/automount-open

If the command does not return at least the example result, this is a finding.)
  desc 'fix', 'Configure RHEL 10 so that the GNOME desktop does not allow a user to change the setting that disables automated mounting of removable media.

Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

Update the "/etc/dconf/db/local.d/locks/00-security-settings-lock" file to prevent user modification:

$ sudo vi /etc/dconf/db/local.d/locks/00-security-settings-lock

/org/gnome/desktop/media-handling/automount-open

Update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-85834r1166769_chk'
  tag severity: 'medium'
  tag gid: 'V-281273'
  tag rid: 'SV-281273r1184699_rule'
  tag stig_id: 'RHEL-10-700700'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-85739r1166770_fix'
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

    profile = command('grep system-db /etc/dconf/profile/user').stdout.strip.match(/:(\S+)$/)[1]

    describe command("grep automount-open /etc/dconf/db/#{profile}.d/locks/*") do
      its('stdout.strip') { should match(%r{^/org/gnome/desktop/media-handling/automount-open}) }
    end
  end
end
