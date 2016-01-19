# monkey: SSH key management app

#### What is this?
This is a program to allow users to self-manage SSH keys.

#### How does it work?
It uses SSH keys and utilities to perform a signature verification against some signed content provided by the user as a password.

#### Can I use it?
Here are the requirements for using this software:
* You NFS mount (or otherwise share) your user's home directories across systems
* You run this software as a user that has sudo permissions to read and write everyone's authorized_keys files
* You do not set passwords on your user accounts (SSH key access only)
* Users have at least 1 SSH key in their authorized_keys file (we do this during user account creation)

##### Todo
* Admin functionality
* Randomized plaintext
