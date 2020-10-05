## Solution for: Train of Thought

### Concept

This challenge is meant to demonstrate one way (levenshtein distance) of hiding numbers in words, and to develop flexibility in approaching a problem

### Solve

The clue is in the name - Dr. Levenshtein. A quick google brings up "Levenshtein Distance", or "Edit Distance", a way of computing the 'distance' between two words. Well, considering that we have a series of words, some suspiciously long and nonsensical, the natural approach is to compute the levenshtein distances between these words

```
dream
(01)
dreams
(14)
fantasticalities
(15)
a
(18)
neuropharmacologist
(07)
neuropharmacy
(01)
neuroharmacy
(14)
psychopathologic
(09)
oneirologic
(26)
dichlorodiphenyltrichloroethane
(05)
dichlorodiphenyltrichloroe
(04)
chlorophenyltrichloroe
(13)
chloromethanes
(09)
fluorines
(14)
cytodifferentiated
(04)
differentiated
```

I used dcode.fr's calculator, though it isn't able to handle words above length 30, so you have to do a little bit of manual legwork on 'dichlorodiphenyltrichloroethane'. After we have the distances, it's just an A1Z26 cipher. Plug it into a solver of your choice, and get the flag.

```
1;14;15;18;7;1;14;9;26;5;4;13;9;14;4 -> anorganizedmind
```

`flag{anorganizedmind}`

