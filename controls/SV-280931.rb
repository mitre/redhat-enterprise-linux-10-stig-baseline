control 'SV-280931' do
  title 'RHEL 10 must ensure cryptographic verification of vendor software packages.'
  desc 'Cryptographic verification of vendor software packages ensures that all software packages are obtained from a valid source and protects against spoofing that could lead to installation of malware on the system. Red Hat cryptographically signs all software packages, including updates, with a GNU Privacy Guard (GPG) key to verify that they are valid.'
  desc 'check', 'Verify RHEL 10 ensures cryptographic verification of vendor software packages.

Confirm Red Hat package-signing keys are installed on the system and verify their fingerprints match vendor values.

Note: For RHEL 10 software packages, Red Hat uses GPG keys labeled "release key 2", "auxiliary key 3", and "release key 4". The keys are defined in key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" by default.

List Red Hat GPG keys installed on the system:

$ sudo rpm -q --queryformat "%{SUMMARY}\\n" gpg-pubkey | grep -i "red hat"
Red Hat, Inc. (release key 2) <security@redhat.com> public key
Red Hat, Inc. (auxiliary key 3) <security@redhat.com> public key
Red Hat, Inc. (release key 4) <security@redhat.com> public key

If Red Hat GPG keys "release key 2", "auxiliary key 3", and "release key 4" are not installed, or if the key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" is missing, this is a finding.

List key fingerprints of installed Red Hat GPG keys:

$ sq inspect /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release: OpenPGP Certificate.

      Fingerprint: 567E347AD0044ADE55BA8A5F199E2F91FD431D51
  Public-key algo: RSA
  Public-key size: 4096 bits
    Creation time: 2009-10-22 11:59:55 UTC
        Key flags: certification, signing

           UserID: Red Hat, Inc. (release key 2) <security@redhat.com>

Note: There is another block of armored OpenPGP data.
Note: This is a non-standard extension to OpenPGP.

/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release: OpenPGP Certificate.

      Fingerprint: 7E4624258C406535D56D6F135054E4A45A6340B3
  Public-key algo: RSA
  Public-key size: 4096 bits
    Creation time: 2022-03-09 21:56:46 UTC
        Key flags: certification, signing

           UserID: Red Hat, Inc. (auxiliary key 3) <security@redhat.com>

Note: There is another block of armored OpenPGP data.
Note: This is a non-standard extension to OpenPGP.

/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release: OpenPGP Certificate.

      Fingerprint: FCD355B305707A62DA143AB6E422397E50FE8467A2A95343D246D6276AFEDF8F
  Public-key algo: ML-DSA-87+Ed448
    Creation time: 2025-10-08 17:40:03 UTC
        Key flags: certification, signing

           UserID: Red Hat, Inc. (release key 4) <security@redhat.com>

Compare key fingerprints of installed Red Hat GPG keys with fingerprints listed for RHEL 10 on the Red Hat "Product Signing Keys" webpage at https://access.redhat.com/security/team/key.

If key fingerprints do not match, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to ensure cryptographic verification of vendor software packages.

Install Red Hat package-signing keys on the system and verify their fingerprints match vendor values.

Insert the RHEL 10 installation disc or attach the RHEL 10 installation image to the system. Mount the disc or image to make the contents accessible inside the system.

Assuming the mounted location is "/media/cdrom", use the following command to copy the Red Hat GPG key file onto the system:

$ sudo cp /media/cdrom/RPM-GPG-KEY-redhat-release /etc/pki/rpm-gpg/

Import Red Hat GPG keys from the key file into the system keyring:

$ sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

Using the steps listed in the Check Text, confirm the newly imported keys show as installed on the system and verify their fingerprints match vendor values.'
  impact 0.5
  tag check_id: 'C-85492r1197212_chk'
  tag severity: 'medium'
  tag gid: 'V-280931'
  tag rid: 'SV-280931r1197213_rule'
  tag stig_id: 'RHEL-10-001020'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-85397r1165147_fix'
  tag 'documentable'
  tag cci: ['CCI-001749', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-14']
  tag 'host'
  tag 'container'

  rpm_gpg_file = input('rpm_gpg_file')
  rpm_gpg_keys = input('rpm_gpg_keys')

  describe file(rpm_gpg_file) do
    it { should exist }
  end
  rpm_gpg_keys.each do |k, v|
    describe command('rpm -q --queryformat "%{SUMMARY}\\n" gpg-pubkey | grep -i "red hat"') do
      its('stdout') { should include k.to_s }
    end
    next unless file(rpm_gpg_file).exist?

    describe command("gpg -q --keyid-format short --with-fingerprint #{rpm_gpg_file}") do
      its('stdout') { should include v }
    end
  end
end
