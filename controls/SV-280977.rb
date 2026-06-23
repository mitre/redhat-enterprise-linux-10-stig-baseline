control 'SV-280977' do
  title 'RHEL 10 must have the Advanced Intrusion Detection Environment (AIDE) package installed.'
  desc 'Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. 

Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (e.g., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.'
  desc 'check', %q(Verify RHEL 10 has the AIDE package installed with the following command:

$ sudo dnf list --installed aide
Installed Packages
aide.x86_64                             0.18.6-8.el10_0.2                             @rhel-10-for-x86_64-appstream-rpms

If AIDE is not installed, ask the system administrator how file integrity checks are performed on the system.

If no application is installed to perform integrity checks, this is a finding.

If AIDE is installed, determine if it has been initialized with the following command:

$ sudo /usr/sbin/aide --check

If the output is "Couldn't open file /var/lib/aide/aide.db.gz for reading", this is a finding.)
  desc 'fix', 'Configure RHEL 10 so that "AIDE" is installed and initialized, and then perform a manual check.

Install AIDE:

$ sudo dnf -y install aide

Initialize AIDE:

$ sudo /usr/sbin/aide --init

Example output:

Start timestamp: 2025-04-03 10:09:04 -0600 (AIDE 0.16)
AIDE initialized database at /var/lib/aide/aide.db.new.gz

Number of entries:      86833

---------------------------------------------------
The attributes of the (uncompressed) database(s):
---------------------------------------------------

/var/lib/aide/aide.db.new.gz
  MD5      : coZUtPHhoFoeD7+k54fUvQ==
  SHA1     : DVpOEMWJwo0uPgrKZAygIUgSxeM=
  SHA256   : EQiZH0XNEk001tcDmJa+5STFEjDb4MPE
             TGdBJ/uvZKc=
  SHA512   : 86KUqw++PZhoPK0SZvT3zuFq9yu9nnPP
             toei0nENVELJ1LPurjoMlRig6q69VR8l
             +44EwO9eYyy9nnbzQsfG1g==

End timestamp: 2025-04-03 10:09:57 -0600 (run time: 0m 53s)

The new database must be renamed to be read by AIDE:

$ sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

Perform a manual check:

$ sudo /usr/sbin/aide --check

Example output:

2025-04-03 10:16:08 -0600 (AIDE 0.16)
AIDE found NO differences between database and filesystem. Looks okay!!

...'
  impact 0.5
  tag check_id: 'C-85538r1195365_chk'
  tag severity: 'medium'
  tag gid: 'V-280977'
  tag rid: 'SV-280977r1195366_rule'
  tag stig_id: 'RHEL-10-200630'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85443r1184613_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
  tag 'host'

  file_integrity_tool = input('file_integrity_tool')

  only_if('Control not applicable within a container', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  if file_integrity_tool == 'aide'
    describe command('/usr/sbin/aide --check') do
      its('stdout') { should_not include "Couldn't open file" }
    end
  end

  describe package(file_integrity_tool) do
    it { should be_installed }
  end
end
