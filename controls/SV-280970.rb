control 'SV-280970' do
  title 'RHEL 10 must enable the "fapolicy" module.'
  desc 'The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as allowlisting.

Using an allowlist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. Verification of allowlisted software occurs prior to execution or at system startup.

User home directories/folders may contain information of a sensitive nature. Nonprivileged users should coordinate any sharing of information with a system administrator through shared resources.

RHEL 10 ships with many optional packages. One such package is a file access policy daemon called "fapolicyd". The "fapolicyd" is a userspace daemon that determines access rights to files based on attributes of the process and file. It can be used to either blocklist or allowlist processes or file access.

Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system nonfunctional. The "fapolicyd" application programming interface (API) is not namespace aware and can cause issues when launching or running containers.

'
  desc 'check', 'Verify RHEL 10 "fapolicyd" is active with the following command:

$ systemctl is-active fapolicyd
active

If the "fapolicyd" module is not active, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enable "fapolicyd" with the following command:

$ systemctl enable --now fapolicyd'
  impact 0.5
  tag check_id: 'C-85531r1165263_chk'
  tag severity: 'medium'
  tag gid: 'V-280970'
  tag rid: 'SV-280970r1165265_rule'
  tag stig_id: 'RHEL-10-200601'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-85436r1165264_fix'
  tag satisfies: ['SRG-OS-000370-GPOS-00155', 'SRG-OS-000368-GPOS-00154']
  tag 'documentable'
  tag cci: ['CCI-001774', 'CCI-001764']
  tag nist: ['CM-7 (5) (b)', 'CM-7 (2)']

  if %w[docker podman kubepods lxc].include?(virtualization.system)
    impact 0.0
    describe 'This requirement is Not Applicable in the container' do
      skip 'This requirement is Not Applicable in the container'
    end
  elsif !input('use_fapolicyd')
    impact 0.0
    describe 'The organization does not use the Fapolicyd service to manage firewall services' do
      skip 'The organization is not using the Fapolicyd service to manage firewall services; this control is Not Applicable'
    end
  else
    describe service('fapolicyd') do
      it { should be_enabled }
      it { should be_running }
    end
  end
end
