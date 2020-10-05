# JS Console
> Complete what Clu could not... Find the data in memory.
> https://www.youtube.com/watch?v=PQwKV7lCzEI

## Step 1 login
- Watching the video you can see that we are trying to login as `CLU` with password `0222`
- There's also client side js that you can look at to find the username and password.
```javascript
function login(username, password) {
    if (username == "CLU" && password == "0222") {
      window.location = "/maze";
    } else window.location = "/";
}
```

## Step 2 maze
- This looks really intimidating
- The maze updates every second and there's a call to `/token` as well
- There's 4 buttons to move Clu through the maze, but the data (the yellow 'o') is always blocked off.
- There's a lot of ways to do this, but you just have to make sure that the token is still constantly updating.

### Wall hax
- You can comment out the checks for walls and just move through them
```javascript
function move_down() {
  let cell = get_cell(x, y + 1);
  if (cell == null) return;
  //if (y == maxRows || cell.style.borderTopStyle != "hidden") return;
  remove_x();
  y += 1;
  add_x();
  check_data();
}
```

### Stop the grid from updating
- Comment out the `CreateGrid()` and `CreateMaze()` functions
```javascript
function CreateAll() {
  Token();
  //CreateGrid();
  add_x();
  add_o();
  //CreateMaze();
}
```

### Teleportation
- Just set the coordinates to be on top of the data
```
x = 1;
// Set x to be 1
y = maxRows;
// Go to bottom
check_data();
// Check the data from the server
```

### TLDR;
- Type this into the console
```
x=1; y=maxRows; check_data();
```
