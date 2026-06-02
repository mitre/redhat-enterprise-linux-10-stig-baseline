control 'SV-280934' do
  title 'RHEL 10 must have GNU Privacy Guard (GPG) signature verification enabled for all software repositories.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.

All software packages must be signed with a cryptographic key recognized and approved by the organization.

Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor.'
  desc 'check', 'Verify RHEL 10 software repositories defined in "/etc/yum.repos.d/" have been configured with "gpgcheck" enabled with the following command:

$ sudo grep -w gpgcheck /etc/yum.repos.d/*.repo | more
gpgcheck = 1

If "localpkg_gpgcheck" is not set to "1", or if the option is missing or commented out, ask the system administrator how the GPG signatures of local software packages are being verified.

If no process to verify GPG signatures has been approved by the organization, this is a finding.'
  desc 'fix', %q(Configure RHEL 10 software repositories defined in "/etc/yum.repos.d/" to have "gpgcheck" enabled with the following command:

$ sudo sed -i 's/gpgcheck\s*=.*/gpgcheck=1/g' /etc/yum.repos.d/*)
  impact 0.7
  tag check_id: 'C-85495r1165155_chk'
  tag severity: 'high'
  tag gid: 'V-280934'
  tag rid: 'SV-280934r1165157_rule'
  tag stig_id: 'RHEL-10-001050'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-85400r1165156_fix'
  tag 'documentable'
  tag cci: ['CCI-001749', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-14']
  tag 'host'
  tag 'container'

  repo_def_files = command('ls /etc/yum.repos.d/*.repo').stdout.split("\n")

  if repo_def_files.empty?
    describe 'No repos found in /etc/yum.repos.d/*.repo' do
      skip 'No repos found in /etc/yum.repos.d/*.repo'
    end
  else
    # pull out all repo definitions from all files into one big hash
    repos = repo_def_files.map { |file| parse_config_file(file).params }.inject(&:merge)

    # check big hash for repos that fail the test condition
    failing_repos = repos.keys.reject { |repo_name| repos[repo_name]['gpgcheck'] == '1' }

    describe 'All repositories' do
      it 'should be configured to verify digital signatures' do
        expect(failing_repos).to be_empty, "Misconfigured repositories:\n\t- #{failing_repos.join("\n\t- ")}"
      end
    end
  end
end
