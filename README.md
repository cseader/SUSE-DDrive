SUSE-DDrive
===========

SUSE Demo Drive for demonstrating SUSE Cloud, SUSE Manager, SUSE Studio, and other SUSE Software

Preparation:
1) create a directory called demo-setup
2) make sure mklapcloud and qa_crowbarsetup.sh are in the directory demo-setup.
3) Download the SUSE Cloud 1.0 ISO image SUSE-CLOUD-1-x86_64-GM-DVD1.iso and put it in the directory demo-setup.
  
There are two more requirements to put this all together. One is a SLES 11 SP2 image. Two is a repos image. 

The SLES 11 SP2 image referenced in the script is sles11sp2-64.img.gz which is a standard image created from an
installation of SLES 11 SP2 on a single raw disk and then once created then gzip the image for size.



