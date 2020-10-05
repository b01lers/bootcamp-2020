Solution for: Goat

First, we are given a .class file. We can only execute this class file, but fortunately for us, we can use many online tools to help us get to the source code. There are 2 java decompilers I used, although many more exist:

 - http://www.javadecompilers.com/
 - http://java-decompiler.github.io/

Now, to solve the chall, we can take a look at the source code. We see that the source code is comparing our input to the number below, so we can copy that in below:
```
"97.122.54.50.93.66.99.117.75.51.101.78.104.119.90.53.94.36.102.84.40.69."
```

These look like ASCII values with dots in between them. Let's seperate them into an array and get the integer values.

Next, we need to start working backwards. In the file, we have an XOR for loop, so we can reverse XOR using several properties:
```
a ^ b = c
a ^ c = b
b ^ c = a
```

Because they are using a random number generator in the XOR for loop, we need the same seed. We can do this by: r.setSeed(431289); We then XOR it back, as per the properties above.

We then see that in the source code, the numbers are getting swapped with the numbers in an array. To reverse this, we can create a new array, which stores the indices of the correct indices.

Lastly, the swap is simply swapping the first and last elements, which we can easily perform.

Because we have been working with integer values the whole time, we want to convert back to char values so we can see the flag! 

The entire Solve.java file can be found seperately with the comments as well!
