control 'SV-281291' do
  title 'RHEL 10 must disable the graphical user interface automounter unless required.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.

'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

Verify RHEL 10 disables the graphical user interface automount function.

Disable the setting with the following command:

$ gsettings get org.gnome.desktop.media-handling automount-open
false

If "automount-open" is set to "true" and is not documented with the information system security officer as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 10 GNOME to disable automated mount of removable media.

Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

Update the "/etc/dconf/db/local.d/00-security-settings" database file with the following lines:

$ sudo vi /etc/dconf/db/local.d/00-security-settings

[org/gnome/desktop/media-handling]
automount-open=false

Update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-85852r1166823_chk'
  tag severity: 'medium'
  tag gid: 'V-281291'
  tag rid: 'SV-281291r1166825_rule'
  tag stig_id: 'RHEL-10-700880'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-85757r1166824_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163']
  tag 'documentable'
  tag cci: ['CCI-000778', 'CCI-001958']
  tag nist: ['IA-3', 'IA-3']
end
