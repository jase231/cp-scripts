printf "MUST BE RUN AS SUDO"
read -p "Press any key to continue ..."
printf "Securing SysCTL ..."
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -p
printf "Updating ..."
apt-get update
apt-get dist-upgrade -y
apt-get install -f -y
apt-get autoremove -y
apt-get autoclean -y
apt-get check
printf "Installing utils"
sudo apt-get install -y chkrootkit clamav rkhunter apparmor apparmor-profiles
printf "Please manually check the resolv.conf file, name server should be 8.8.8.8. File opening now."
read -p "Press any key to continue ..."
nano /etc/resolv.conf
printf "Manually check hosts file. Make sure there arent any sussy redirects. File opening now."
read -p "Press any key to continue ..."
nano /etc/hosts
printf "Setting proper RW Perms and locking root account (unlock with usermod -U root)..."
chmod 604 /etc/shadow
chmod 640 .bash_history
usermod -L root
printf "Backing up rc.local to desktop and clearing startup scripts ..."
cp /etc/rc.local ~/Desktop/backups/
echo > /etc/rc.local
echo 'exit 0' >> /etc/rc.local
printf "Installing mlocate and updating db ..."
sudo apt-get install -y mlocate
sudo updatedb
printf "Installing and configing SSH"
sudo apt-get install -y openssh-server ssh
sed -i 's/LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i '$a AllowUsers' /etc/ssh/sshd_config
printf "This script is now complete, downloading guide ..."
curl https://s3.amazonaws.com/cpvii/Training+materials/Unit+Eight+-+Ubuntu+Security.pdf --output guide.pdf