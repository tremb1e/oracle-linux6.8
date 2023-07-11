# oracle-linux6.8
kernel code and others
tse-utils and rpm are in /others

#to compile kernel and tse-utils
yum -y groupinstall "development tools" ncurses-devel 

make menuconfig 

make
