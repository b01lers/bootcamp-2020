Solution for: Needle In A Haystack

We are given a zip file. Let's start by unzipping. Most devices can unzip by just double clicking, or we can use: unzip haystack.zip

After unzipping, we are given a folder, let's go into that directory with cd

We see a bunch of text files, if we open any of them up, we see a bunch of gibberish.
The name of the challenge provides us a clue, there is a haystack, and we have to find the needle, or in this case the flag. We know that the flag will be in flag{} format, so we can use that to our advantage. We also know that all the files are .txt files.

We can use this command to get the flag: cat *.txt | grep "flag{"

Why this command works: 

cat - outputs the contents of the file

*.txt - any file that ends with .txt

| grep "flag{" - specifically look for flag{
