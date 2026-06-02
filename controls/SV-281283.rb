control 'SV-281283' do
  title 'RHEL 10 must ensure effective dconf policy matches the policy keyfiles.'
  desc 'Unlike text-based keyfiles, the binary database is impossible to check through most automated and all manual means; therefore, to evaluate dconf configuration, both must be true at the same time. Configuration files must be compliant, and the database must be more recent than those keyfiles, which gives confidence that it reflects them.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

Verify RHEL 10 ensures effective dconf policy matches the policy keyfiles.

Check the last modification time of the local databases, comparing it to the last modification time of the related keyfiles. The following command will check every dconf database and compare its modification time to the related system keyfiles:

$ function dconf_needs_update { for db in $(find /etc/dconf/db -maxdepth 1 -type f); do db_mtime=$(stat -c %Y "$db"); keyfile_mtime=$(stat -c %Y "$db".d/* | sort -n | tail -1); if [ -n "$db_mtime" ] && [ -n "$keyfile_mtime" ] && [ "$db_mtime" -lt "$keyfile_mtime" ]; then echo "$db needs update"; return 1; fi; done; }; dconf_needs_update

If the command has any output, then a dconf database needs to be updated, and this is a finding.'
  desc 'fix', 'Configure RHEL 10 to ensure that the effective dconf policy matches the policy keyfiles.

Update the dconf databases by running the following command:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-85844r1166799_chk'
  tag severity: 'medium'
  tag gid: 'V-281283'
  tag rid: 'SV-281283r1166801_rule'
  tag stig_id: 'RHEL-10-700800'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85749r1166800_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
