control 'SV-281006' do
  title 'RHEL 10 must have the "gnutls-utils" package installed.'
  desc '"GnuTLS" is a secure communications library implementing the Secure Sockets Layer (SSL), Transport Layer Security (TLS), and Datagram TLS (DTLS) protocols and technologies around them. It provides a simple C language application programming interface (API) to access the secure communications protocols as well as APIs to parse and write X.509, PKCS #12, OpenPGP, and other required structures. This package contains command line TLS client and server and certificate manipulation tools.'
  desc 'check', 'Verify RHEL 10 has the "gnutls-utils" package installed with the following command:

$ sudo dnf list --installed gnutls-utils
Installed Packages
gnutls-utils.x86_64                         3.8.9-9.el10_0.14                         @rhel-10-for-x86_64-appstream-rpms

If the "gnutls-utils" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "gnutls-utils" package installed with the following command:

$ sudo dnf -y install gnutls-utils'
  impact 0.5
  tag check_id: 'C-85567r1195396_chk'
  tag severity: 'medium'
  tag gid: 'V-281006'
  tag rid: 'SV-281006r1195397_rule'
  tag stig_id: 'RHEL-10-200740'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85472r1165372_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
  tag 'host'
  tag 'container'

  describe package('gnutls-utils') do
    it { should be_installed }
  end
end
