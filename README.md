# S-PMU

# Update Status
We are in the process of updating the current S-PMU framework with addtional security mechanisms and docuemnt the frameowrk as journal paper.
We hope to release update S-PMU frameork sometime during 2021.





#Programs:

1. PMU_simulator_without_security.c 

	This program defines all the necessary fields of IEEE C37.118.2 protocol and send it to destination device. 

Commands to execute the program at terminal  
Step 1: Run 'ifconfig' Linux command at terminal to know the interface name and sender device MAC address. 
	
	$ ifconfig
	
Step 2: Set Destination MAC address in the program to 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF values in case of broadcasting the PMU packets in the network. 

Step 3: Compilation of program

	$ gcc -o PMU_sender_without_security  PMU_sender_without_security.c 
	
Step 4: To run the code

	$./ PMU_sender_without_security

2. PMU_simulator_with_security_only_mac.c 
 
	This program generates a MAC value for C37.118.2 data frame using HMAC function which is defined in openSSL library and send secure PMU packet to destination device. 

Commands to execute the program at terminal

Step 1: Install openssl library if not installed using the following command. 

	$ sudo apt-get install libssl-dev
	
Step 2: Run 'ifconfig' Linux command at terminal to know the interface name and sender device MAC address. 

	$ ifconfig
	
Step 3: Set Destination MAC address in the program to 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF values in case of broadcasting the PMU packets in the network. 

Step 4: Compilation of program

	$ gcc -o PMU_simulator_with_security_only_mac  PMU_simulator_with_security_only_mac.c -L /usr/local/lib/ -lssl -lcrypto 

Step 4: To run the code

	$./PMU_simulator_with_security_only_mac  


3. PMU_simulator_with_security_enc_mac.c 

	This program encrypts the IEEE C37.118.2 payload field and generates a MAC value using AES 256 GCM and HMAC-SHA256. The encryption and MAC functions are defined in openSSL library. 
	
Commands to execute the program at terminal

Step 1: Install openssl library if not installed using the following command. 

	$ sudo apt-get install libssl-dev
	
Step 2: Run ifconfig at terminal to know the interface name and sender device MAC address. 

	$ ifconfig
	
Step 3: Set Destination MAC address in the program to 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF values in case of broadcasting the PMU packets in the network. 

Step 4: Compilation of program

	$ gcc -o PMU_simulator_with_security_enc_mac  PMU_simulator_with_security_enc_mac.c  
	
Step 4: To run the code

	$./PMU_simulator_with_security_enc_mac  




