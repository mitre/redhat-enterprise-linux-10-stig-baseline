control 'SV-280937' do
  title 'RHEL 10 must use a separate file system for user home directories (such as "/home" or an equivalent).'
  desc 'Ensuring that "/home" is mounted on its own partition enables the setting of more restrictive mount options and helps ensure that users cannot trivially fill partitions used for log or audit data storage.'
  desc 'check', 'Verify RHEL 10 uses a separate file system/partition for "/home" with the following command:

$ mount | grep /home
/dev/mapper/luks-ca2261ed-7b00-4b7b-84cd-8cd6d8fa4b28 on /home type xfs (rw,nodev,nosuid,noexec,seclabel)
Note: Options displayed for mount may differ.

If a separate entry for "/home" is not in use, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to use a separate file system for user home directories by migrating the "/home" directory onto a separate file system/partition.'
  impact 0.5
  tag check_id: 'C-85498r1165164_chk'
  tag severity: 'medium'
  tag gid: 'V-280937'
  tag rid: 'SV-280937r1184727_rule'
  tag stig_id: 'RHEL-10-000530'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85403r1165165_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
