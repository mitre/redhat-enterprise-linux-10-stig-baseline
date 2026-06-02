control 'SV-280979' do
  title 'RHEL 10 must use a file integrity tool that is configured to use FIPS 140-3-approved cryptographic hashes for validating file contents and directories.'
  desc 'RHEL 10 installation media ships with an optional file integrity tool called Advanced Intrusion Detection Environment (AIDE). AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory.

File integrity tools use cryptographic hashes for verifying that file contents and directories have not been altered. These hashes must be FIPS 140-3-approved cryptographic hashes.'
  desc 'check', %q(Verify RHEL 10 AIDE is configured to use FIPS 140-3 file hashing.

Verify global default hash settings with the following command:

$ sudo grep -iE 'sha|md5|rmd' /etc/aide.conf | grep -v ^#
FIPSR = p+i+n+u+g+s+m+ftype+growing+acl+selinux+xattrs+sha512
ALLXTRAHASHES = sha512
/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
NORMAL = FIPSR+sha512
LSPP = FIPSR+sha512
DATAONLY =  R+sha512
/etc/gshadow  NORMAL
/etc/shadow   NORMAL

If any hashes other than "sha512" are present, this is a finding.

Confirm no legacy hashes exist with the following command:

$ sudo grep -iE 'md5|sha1|whirlpool|tiger' /etc/aide.conf | grep -v ^#

If any uncommented lines are returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 so that the file integrity tool uses FIPS 140-3 cryptographic hashes for validating file and directory contents.

If AIDE is installed, ensure the "sha512" rule is present on all uncommented file and directory selection lists, and that no legacy hashes exist. 

By default, AIDE excludes log files such as "/var/log" and other volatile files to reduce unnecessary notifications.'
  impact 0.5
  tag check_id: 'C-85540r1165290_chk'
  tag severity: 'medium'
  tag gid: 'V-280979'
  tag rid: 'SV-280979r1165292_rule'
  tag stig_id: 'RHEL-10-200632'
  tag gtitle: 'SRG-OS-000404-GPOS-00183'
  tag fix_id: 'F-85445r1165291_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002475']
  tag nist: ['CM-6 b', 'SC-28 (1)']
  tag 'host'

  file_integrity_tool = input('file_integrity_tool')

  only_if('Control not applicable within a container', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  if file_integrity_tool == 'aide'
    describe parse_config_file('/etc/aide.conf') do
      its('All') { should match(/sha512/) }
    end
  else
    describe 'Manual Review' do
      skip "Review the selected file integrity tool (#{file_integrity_tool}) configuration to ensure it is using FIPS 140-2/140-3-approved cryptographic hashes for validating file contents and directories."
    end
  end
end
