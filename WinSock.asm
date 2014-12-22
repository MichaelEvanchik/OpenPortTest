.386
.model flat, stdcall
option casemap: none
include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc
include \masm32\include\shell32.inc
include \masm32\include\wsock32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\shell32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\wsock32.lib
includelib \masm32\lib\masm32.lib

.data
 usage   db  "                                    ",13,10,\
usage2   db  "[*] Usage:   p.exe <ip>     [*]",13,10,\
             "[*] Example: detect 192.168.1.1  [*]",13,10,0
 STARTme   db "[+] Finding Host %s",0Dh,0Ah,0
 HostYay   db "[+] Connected to %s",0Dh,0Ah,0
 HostErr   db "[-] Cannot connect to %s",0Dh,0Ah,0
 LoginRcv  db "[+] %s",0Dh,0Ah,0

.data?
	IPAddress  db 128 dup(?)
	buffer     db 128 dup(?)
	sock       dd ?
	sin        sockaddr_in <?>
	wsadata		 WSADATA <?>
	buff_sock  db 1600 dup (?)

.code
@@start:
	invoke GetCL, 1, addr IPAddress
	cmp eax, 1
	jnz @@usage
  invoke StdOut, addr usage
	invoke WSAStartup, 101h, offset wsadata
	test eax, eax
	jnz @@start
	invoke socket, AF_INET, SOCK_STREAM, 0
	mov sock, eax
	mov sin.sin_family, AF_INET
	invoke htons, 445
	mov sin.sin_port, ax
	invoke inet_addr, addr IPAddress
	mov sin.sin_addr, eax
	invoke wsprintf, addr buffer, addr STARTme, addr IPAddress
	invoke StdOut, addr buffer
	invoke connect, sock, addr sin, sizeof sin
	cmp eax, SOCKET_ERROR
	jz @@connect_err
	invoke wsprintf,addr buffer,addr HostYay,addr IPAddress
	invoke StdOut, addr buffer
	invoke closesocket, sock
	invoke WSACleanup
	invoke ExitProcess, 0
	
@@connect_err:
	invoke wsprintf,addr buffer,addr HostErr,addr IPAddress
	invoke	StdOut,addr buffer

@@usage:
	invoke StdOut, addr usage
  invoke StdOut, addr usage2

  
@@err:
	invoke closesocket, sock
	invoke WSACleanup
	invoke ExitProcess, 0
	ret
end @@start
