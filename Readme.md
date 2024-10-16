[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/sTWZcGok)
# Cloud Developer REU Programming Test
Thank you for your interest in our REU position. Before proceeding to the next phase of the application process, you have one week to complete the following programming test to evaluate your programming skills. The test consists of two tasks: debugging and enhancing a C program for network traffic analysis.
## Background
The program is available in the repository and includes two files, `original.c` and `testdata.pcap`. The `original.c` code is designed to print out the destination IP addresses in `testdata.pcap` but is not working correctly. 


## Compile and run the code
To compile this code, you'll need to link against the pcap library. On Linux or macOS, you can do this by adding `-lpcap` to the `gcc` command:
```sh
gcc -o original original.c -lpcap
```
Then, you can run the program by passing the name of the pcap file as the command line argument:
```sh
./original testdata.pcap
```
## Task 1: Debug the code
Your first task is to debug it by identifying and fixing the problem in a copy of the `original code` renamed as `modified.c`. Add comments near the lines that you modify to explain your changes.
The code is supposed to print out the destination IP address of each packet similar to the following:
```
Packet 1: IP destination address: 10.0.0.253
Packet 2: IP destination address: 10.0.0.11
Packet 3: IP destination address: 10.0.0.159
Packet 4: IP destination address: 10.0.0.208
Packet 5: IP destination address: 10.0.0.220
Packet 6: IP destination address: 10.0.0.10
Packet 7: IP destination address: 10.0.0.92
Packet 8: IP destination address: 10.0.0.162
Packet 9: IP destination address: 10.0.0.147
Packet 10: IP destination address: 10.0.0.204
...
```
However, the current version of the code returns: 
```
Segmentation fault (core dumped)
```

## Task 2: Enhance the code
Once you have debugged the code, your second task is to enhance it. Create a copy of `modified.c` called `enhanced.c`. Your enhancement should be to count the occurrences of different last octet values in the destination IPs. Add comments to explain your implementation.

The new feature you are going to implement is to count the occurance of different last octet values in the desination IPs. For example, the last octet of Packet 1 in `testdata.pcap` is 253. Your program should print the number of occurances of each last octet value, similar to the following:
```
Last octet 0: XXX
Last octet 1: YYY
...
```
Note that you only use the POSIX C library to implement this feature. You are also required to read directly from the pcap file. In other words, you are not allowed to invoke other programs/scripts in your code or process the output in task 1.

## Submission
You have 1 week to complete this test. Push your code to github and send your github classroom respository to cskpmok <AT> caida.org. 
