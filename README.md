# QSDK-Demo
These are resources. Include build tools, and other useful information.

find ./toolchain-mips_34kc_gcc-4.8-linaro_uClibc-1.0.14/ -type f -print0 | xargs -0 md5sum | sort > md5_check.txt 
Use the command to generate md5 for all files in the toolchain, and compare with the md5.txt file in the folder to check the download is complete.
