## Solution for: Lava Fight

### Concept

A huge part of reverse engineering is in game modding and hacking. This challenge is a multiplayer platform shooter that has a server that is woefully equipped to verify anything. 

### Solve

We're given three tasks:
1. Go as fast as you can.
2. Grow from pain.
3. Destroy all five of your enemies in the blink of an eye.

So we can infer that to mean:
1. Go faster than we're normally allowed to
2. Don't take damage when we get hit (or increase our health instead)
3. Destroy 5 enemies in a server tick.

We have all the code (a .love file is just a zip) so we can super easily mod this game!

I'm not going to go into detail but for each task:

1. Modify Player.runSpeed to be more like....1k
2. Change takeDamage to do Player.hp += 1 instead of - 1
3. Modify the fire() method to not check that we are under our cooldown timer before we fire again.

The `hacked` directory is an example of a hacked game.

