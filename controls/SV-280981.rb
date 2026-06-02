control 'SV-280981' do
  title 'RHEL 10 must be configured so that the file integrity tool verifies Access Control Lists (ACLs).'
  desc 'RHEL 10 installation media ships with an optional file integrity tool called Advanced Intrusion Detection Environment (AIDE). AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory.

ACLs can provide permissions beyond those permitted through the file mode and must be verified by the file integrity tools.'
  desc 'check', %q(Verify RHEL 10 AIDE is verifying ACLs.

Verify ACL settings for all uncommented file and directory selection lists with the following command:

$ sudo grep -E '^[^#]*acl' /etc/aide.conf
FIPSR = p+i+n+u+g+s+m+growing+acl+selinux+xattrs+sha512
/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
DIR = p+i+n+u+g+acl+selinux+xattrs
PERMS = p+i+u+g+acl+selinux

Open the file and verify no additional uncommented file and directory selection lines are missing the "acl" rule.

If the "acl" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or ACLs are not being checked by another file integrity tool, this is a finding.)
  desc 'fix', 'Configure RHEL 10 so that the file integrity tool checks file and directory ACLs.

If AIDE is installed, ensure the "acl" rule is present on all uncommented file and directory selection lists.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000404-GPOS-00183'
  tag gid: 'V-280981'
  tag rid: 'SV-280981r1165298_rule'
  tag stig_id: 'RHEL-10-200634'
  tag fix_id: 'F-85447r1165297_fix'
  tag cci: ['CCI-000366', 'CCI-002475']
  tag nist: ['CM-6 b', 'SC-28 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  describe package('aide') do
    it { should be_installed }
  end

  findings = []
  aide_conf.where { !selection_line.start_with? '!' }.entries.each do |selection|
    findings.append(selection.selection_line) unless selection.rules.include? 'acl'
  end

  describe "List of monitored files/directories without 'acl' rule" do
    subject { findings }
    it { should be_empty }
  end
end
