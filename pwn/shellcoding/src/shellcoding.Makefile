shellcoding: shellcoding.c
	gcc shellcoding.c -o shellcoding -no-pie -O0 -z execstack
