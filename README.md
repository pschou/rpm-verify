# RPM Verify

A simple tool to verify an RPM against a PGP keyring.

## Usage
```
$ ./rpm-verify 
rpm-verify,  Version: 0.1.20221020.2205 (https://github.com/pschou/rpm-verify)

Usage: rpm-verify [options] test.rpm

  -keyring string
        Use keyring for verifying, keyring.gpg or keys/ directory (default "keys/")
```

## Example
```
$ ./rpm-verify -keyring SALTSTACK-GPG-KEY.pub libsodium-devel-1.0.18-1.el7.x86_64.rpm
  1) Loaded Primary Key (0xE08A149DE57BFBE)
     Sub Key (0xD34246317928113)
opening: libsodium-devel-1.0.18-1.el7.x86_64.rpm
Signed by: SaltStack Packaging Team <packaging@saltstack.com> (e08a149de57bfbe)
$ echo $?
0
```
